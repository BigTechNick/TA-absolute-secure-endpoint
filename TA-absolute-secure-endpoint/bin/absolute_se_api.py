# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
absolute_se_api.py - client for the Absolute API (Absolute Secure Endpoint).

Every call is a GET request described in a JWS (HS256, signed with the API
token's secret key) and sent as the body of a POST to
https://<api host>/jws/validate, the way Absolute documents its API.

  * sign_request(): the signed request
  * Client.get(): one call, with retries for rate limits and server errors
  * siem_event_pages(): /v3/reporting/siem-events for a time window, page by page
  * device_pages(): /v3/reporting/devices-advanced, page by page
  * parse_properties(): an event's objectProperties text as a dict

Standard library only; runs on Splunk's bundled Python 3.9 and 3.13.
"""
import base64
import calendar
import hashlib
import hmac
import http.client
import json
import os
import random
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

APP_VERSION = "1.0.1"
USER_AGENT = f"TA-absolute-secure-endpoint/{APP_VERSION}"
SIEM_EVENTS = "/v3/reporting/siem-events"
DEVICES = "/v3/reporting/devices-advanced"
VALIDATE = "/jws/validate"

# Absolute's API hosts: api.absolute.com and the regional ones (api.<region>.absolute.com).
API_HOST_RE = re.compile(r"^api(?:\.[a-z0-9-]{1,30})?\.absolute\.com$")
TOKEN_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,128}$")
PROXY_RE = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]+(?::\d{1,5})?/?$")

RETRY_STATUS = (408, 425, 429, 500, 502, 503, 504)
MAX_ATTEMPTS = 6
MAX_WAIT = 300


class ApiError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


# ------------------------------------------------------------------ signing

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def hs256(secret, signing_input):
    return hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()


def sign_request(token_id, secret, uri, query, issued_at_ms=None):
    """Compact JWS (header.payload.signature) describing GET <uri>?<query>."""
    header = {
        "alg": "HS256",
        "kid": token_id,
        "method": "GET",
        "content-type": "application/json",
        "uri": uri,
        "query-string": query,
        "issuedAt": int(time.time() * 1000) if issued_at_ms is None else issued_at_ms,
    }
    payload = {"data": {}}
    signing_input = (b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")) + "." +
                     b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")))
    return signing_input + "." + b64url(hs256(secret, signing_input))


# ------------------------------------------------------------------ time

def utc_text(epoch):
    """2026-10-22T19:34:05.000Z (whole seconds, as Absolute's own connector sends them)."""
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(int(epoch)))


def utc_text_ms(epoch):
    """2026-10-22T19:34:05.123Z"""
    whole = int(epoch)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(whole)) + ".%03dZ" % int(round((epoch - whole) * 1000) % 1000)


ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|[+-]00:?00)?$")


def parse_utc(text):
    """Absolute's UTC timestamps (2026-10-22T19:29:30.000Z) -> epoch seconds, or None."""
    m = ISO_RE.match((text or "").strip())
    if not m:
        return None
    parts = [int(x) for x in m.groups()[:6]]
    frac = m.group(7) or "0"
    try:
        return calendar.timegm((parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], 0, 0, 0)) + \
            float("0." + frac)
    except (OverflowError, ValueError):
        return None


# ------------------------------------------------------------------ http

def ssl_context():
    """System CAs, plus the bundle that ships with Splunk's Python (certifi) and common system bundles."""
    ctx = ssl.create_default_context()
    if hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    extra = []
    try:
        import certifi
        extra.append(certifi.where())
    except Exception:
        pass
    extra += ["/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"]
    for path in extra:
        if path and os.path.isfile(path):
            try:
                ctx.load_verify_locations(cafile=path)
            except (ssl.SSLError, OSError):
                pass
    return ctx


def error_message(status, body):
    """Short message from an Absolute error response."""
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body or "")
    try:
        doc = json.loads(text)
        if isinstance(doc, dict):
            for key in ("message", "error_description", "error", "errors", "detail", "title"):
                value = doc.get(key)
                if value:
                    if isinstance(value, (list, dict)):
                        value = json.dumps(value)[:300]
                    return f"HTTP {status}: {value}"
    except ValueError:
        pass
    text = " ".join(text.split())
    return f"HTTP {status}: {text[:300]}" if text else f"HTTP {status}"


HINTS = {
    401: "the API token was not accepted (wrong token ID or secret key, or the token was deleted or disabled)",
    403: "the API token lacks permission for this data, or the request came from an IP address the token "
         "does not allow",
}


class Client:
    """
    One Absolute account: API host, token ID and secret key, optional HTTPS proxy.
    should_stop: a function; when it returns True, retries and waits end early.
    """

    def __init__(self, api_host, token_id, token_secret, proxy_url="", timeout=120, log=None,
                 should_stop=None, max_attempts=MAX_ATTEMPTS):
        if not API_HOST_RE.match(api_host or ""):
            raise ApiError(f"API host {api_host!r} is not an Absolute API host (api[.<region>].absolute.com)")
        self.api_host = api_host
        self.token_id = token_id
        self.token_secret = token_secret
        self.timeout = timeout
        self.log = log
        self.should_stop = should_stop or (lambda: False)
        self.max_attempts = max_attempts
        self.calls = 0
        self.retries = 0
        handlers = [urllib.request.HTTPSHandler(context=self.make_ssl_context())]
        if proxy_url:
            handlers.append(urllib.request.ProxyHandler({"https": proxy_url, "http": proxy_url}))
        self.opener = urllib.request.build_opener(*handlers)

    # Tests point these at a local server.
    def base_url(self):
        return f"https://{self.api_host}"

    def make_ssl_context(self):
        return ssl_context()

    def _sleep(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            if self.should_stop():
                raise ApiError("stopped")
            time.sleep(min(1.0, max(0.0, end - time.time())))

    def get(self, uri, query):
        """GET uri?query through /jws/validate; returns the parsed JSON body."""
        attempt = 0
        while True:
            attempt += 1
            if self.should_stop():
                raise ApiError("stopped")
            body = sign_request(self.token_id, self.token_secret, uri, query).encode("ascii")
            req = urllib.request.Request(self.base_url() + VALIDATE, data=body, method="POST", headers={
                "Content-Type": "text/plain", "Accept": "application/json", "User-Agent": USER_AGENT})
            status, payload, wait = None, b"", None
            self.calls += 1
            try:
                with self.opener.open(req, timeout=self.timeout) as resp:
                    status = resp.status
                    payload = resp.read()           # IncompleteRead (HTTPException) is retried below
            except urllib.error.HTTPError as exc:
                status = exc.code
                try:
                    payload = exc.read()
                except Exception:
                    payload = b""
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                if retry_after and retry_after.strip().isdigit():
                    wait = min(int(retry_after.strip()), MAX_WAIT)
            except (urllib.error.URLError, http.client.HTTPException, socket.timeout, ConnectionError, ssl.SSLError,
                    OSError) as exc:
                reason = getattr(exc, "reason", exc)
                if isinstance(reason, ssl.SSLCertVerificationError) or isinstance(exc, ssl.SSLCertVerificationError):
                    raise ApiError(f"TLS certificate of {self.api_host} could not be verified ({reason}). "
                                   "If a proxy inspects TLS, add its CA to the system CA bundle.")
                message = f"cannot reach {self.api_host}: {reason}"
                if attempt >= self.max_attempts:
                    raise ApiError(message)
                self._retry(attempt, message, None)
                continue

            if status == 200:
                try:
                    doc = json.loads(payload.decode("utf-8"))
                except (ValueError, UnicodeDecodeError) as exc:
                    raise ApiError(f"response from {uri} is not JSON ({exc})", status)
                if not isinstance(doc, dict):
                    raise ApiError(f"unexpected response from {uri}", status)
                return doc
            message = error_message(status, payload)
            if status in RETRY_STATUS and attempt < self.max_attempts:
                self._retry(attempt, message, wait)
                continue
            if status in HINTS:
                message += f" - {HINTS[status]}"
            raise ApiError(f"{uri}: {message}", status)

    def _retry(self, attempt, message, wait):
        if wait is None:
            wait = min(2 ** attempt * 2, 120) + random.uniform(0, 2)
        self.retries += 1
        if self.log:
            self.log.warning("%s - retry %d of %d in %.0f s", message, attempt, self.max_attempts - 1, wait)
        self._sleep(wait)


def next_page_of(doc):
    meta = doc.get("metadata") if isinstance(doc, dict) else None
    pagination = meta.get("pagination") if isinstance(meta, dict) else None
    value = pagination.get("nextPage") if isinstance(pagination, dict) else None
    return value if isinstance(value, str) and value else ""


def records_of(doc):
    data = doc.get("data") if isinstance(doc, dict) else None
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


MAX_PAGES = 100000


def _pages(client, uri, base_query):
    """Follows nextPage until the last page. Yields (records, page number)."""
    query, seen, page = base_query, set(), 0
    while True:
        page += 1
        doc = client.get(uri, query)
        records = records_of(doc)
        yield records, page
        token = next_page_of(doc)
        if not token or not records:
            return
        if token in seen or page >= MAX_PAGES:
            raise ApiError(f"{uri}: the API returned the same next page twice ({token[:40]}); stopping")
        seen.add(token)
        query = f"nextPage={token}" + ("&" + base_query if base_query else "")


def siem_event_pages(client, start, end, page_size):
    """SIEM events Absolute recorded between start and end (epoch seconds), page by page."""
    base = f"pageSize={int(page_size)}&fromDateTimeUtc={utc_text(start)}&toDateTimeUtc={utc_text(end)}"
    return _pages(client, SIEM_EVENTS, base)


def device_query(connected_since=None, page_size=0):
    parts = []
    if connected_since is not None:
        stamp = urllib.parse.quote_plus(utc_text_ms(connected_since))
        parts.append(f"filter=lastConnectedDateTimeUtcFrom%20eq%20%27{stamp}%27")
    if page_size:
        parts.append(f"pageSize={int(page_size)}")
    return "&".join(parts)


def device_pages(client, connected_since=None, page_size=0):
    """
    Devices (devices-advanced), page by page. connected_since (epoch seconds): only devices that
    connected since then; None: every device in the account, including retired ones.
    """
    query = device_query(connected_since, page_size)
    page, token, seen = 0, "", set()
    while True:
        page += 1
        q = query if not token else (query + "&" if query else "") + f"nextPage={token}"
        doc = client.get(DEVICES, q)
        records = records_of(doc)
        yield records, page
        token = next_page_of(doc)
        if not token or not records:
            return
        if token in seen or page >= MAX_PAGES:
            raise ApiError(f"{DEVICES}: the API returned the same next page twice; stopping")
        seen.add(token)


# --------------------------------------------------------------- properties

PROP_RE = re.compile(r"PropertyName(?:\[(\d+)\])?=")


def parse_properties(text, event_type=""):
    """
    objectProperties ("PropertyName[1]=Latitude;OldValue[1]=12.5;NewValue[1]=12.6;...", or without
    the [n] when there is one property) -> {"Latitude": {"old": "12.5", "new": "12.6"}, ...}.
    A name that repeats the event type ("DeviceNetworkAdapterUpdated.IpV4Address") loses that
    prefix ("IpV4Address"). Empty old or new values are left out.
    """
    out = {}
    if not text or not isinstance(text, str):
        return out
    marks = list(PROP_RE.finditer(text))
    prefix = (event_type + ".") if event_type else ""
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        seg = text[m.end():end]
        tag = f"[{m.group(1)}]" if m.group(1) else ""
        old_tag, new_tag = f";OldValue{tag}=", f";NewValue{tag}="
        o = seg.find(old_tag)
        n = seg.find(new_tag, o + len(old_tag) if o >= 0 else 0)
        if o < 0 and n < 0:
            name, old, new = seg.rstrip(";"), "", ""
        elif o < 0:
            name, old, new = seg[:n], "", seg[n + len(new_tag):]
        elif n < 0:
            name, old, new = seg[:o], seg[o + len(old_tag):], ""
        else:
            name, old, new = seg[:o], seg[o + len(old_tag):n], seg[n + len(new_tag):]
        if new.endswith(";"):
            new = new[:-1]
        elif old.endswith(";") and not new:
            old = old[:-1]
        name = name.strip()
        if not name:
            continue
        if prefix and name.startswith(prefix) and len(name) > len(prefix):
            name = name[len(prefix):]
        key, k = name, 2
        while key in out:
            key = f"{name}_{k}"
            k += 1
        value = {}
        if old != "":
            value["old"] = old
        if new != "":
            value["new"] = new
        out[key] = value
    return out
