#!/usr/bin/env python3
"""unit_api.py - JWS signing, objectProperties parsing, time formats, and the API client against fake_absolute."""
import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
APP_BIN = os.path.join(os.path.dirname(HERE), "TA-absolute-secure-endpoint", "bin")
sys.path[:0] = [APP_BIN, HERE]
import absolute_se_api as api  # noqa: E402
import fake_absolute as fake  # noqa: E402

FAILS = []


def check(cond, label):
    print(("PASS  " if cond else "FAIL  ") + label)
    if not cond:
        FAILS.append(label)


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---- JWS: RFC 7515 appendix A.1 (HS256) vector for the base64url and HMAC steps
signing_input = ("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6"
                 "Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")
key = b64d("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
sig = api.b64url(hmac.new(key, signing_input.encode(), hashlib.sha256).digest())
check(sig == "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "RFC 7515 A.1 HS256 signature")

jws = api.sign_request("tok-id", "s3cret", "/v3/reporting/siem-events", "pageSize=1", issued_at_ms=1700000000000)
h, p, s = jws.split(".")
header = json.loads(b64d(h))
check(header == {"alg": "HS256", "kid": "tok-id", "method": "GET", "content-type": "application/json",
                 "uri": "/v3/reporting/siem-events", "query-string": "pageSize=1", "issuedAt": 1700000000000},
      "JWS header carries alg, kid, method, content-type, uri, query-string, issuedAt (ms)")
check(json.loads(b64d(p)) == {"data": {}}, "JWS payload is {\"data\": {}}")
check(b64d(s) == hmac.new(b"s3cret", f"{h}.{p}".encode(), hashlib.sha256).digest(), "JWS signed with the secret key")
check("=" not in jws, "JWS is unpadded base64url")

# ---- objectProperties
P = api.parse_properties
check(P("PropertyName[1]=ApplicationName;OldValue[1]=;NewValue[1]=Example Notes;PropertyName[2]=ApplicationVersion;"
        "OldValue[2]=;NewValue[2]=1.2.3;") ==
      {"ApplicationName": {"new": "Example Notes"}, "ApplicationVersion": {"new": "1.2.3"}}, "indexed properties")
check(P("PropertyName=DeviceSystemInformationUpdated.PublicIpAddr;OldValue=198.51.100.7;NewValue=198.51.100.9;",
        "DeviceSystemInformationUpdated") == {"PublicIpAddr": {"old": "198.51.100.7", "new": "198.51.100.9"}},
      "single property without [n]; event type prefix removed")
check(P("PropertyName[1]=Gps.ErrorKey;OldValue[1]=;NewValue[1]=com.example;", "DeviceLocationUpdated") ==
      {"Gps.ErrorKey": {"new": "com.example"}}, "other dotted names kept")
check(P("PropertyName=description;OldValue=;NewValue=test; with semicolon;") ==
      {"description": {"new": "test; with semicolon"}}, "value containing ';'")
check(P("PropertyName[1]=X;OldValue[1]=a=b;NewValue[1]=c;") == {"X": {"old": "a=b", "new": "c"}}, "value containing '='")
check(P("PropertyName[1]=X;OldValue[1]=1;NewValue[1]=2;PropertyName[2]=X;OldValue[2]=3;NewValue[2]=4;") ==
      {"X": {"old": "1", "new": "2"}, "X_2": {"old": "3", "new": "4"}}, "repeated name kept as X_2")
check(P("PropertyName=Status;OldValue=INST;") == {"Status": {"old": "INST"}}, "no NewValue")
check(P("") == {} and P(None) == {} and P(12) == {}, "empty or not text")
long_value = ", ".join(f"Ext {i}" for i in range(500))
check(P(f"PropertyName=Value;OldValue={long_value};NewValue={long_value}, More;")["Value"]["new"].endswith("More"),
      "long value")
check(P("PropertyName[1]=Location;OldValue[1]=In;NewValue[1]=Out;PropertyName[2]=InsideGeofence;OldValue[2]=a,b;"
        "NewValue[2]=a;")["InsideGeofence"] == {"old": "a,b", "new": "a"}, "geofence lists")

# ---- time
check(api.utc_text(1761161645.9) == "2025-10-22T19:34:05.000Z", "window time: whole seconds, .000Z")
check(api.utc_text_ms(1761161645.25) == "2025-10-22T19:34:05.250Z", "device filter time: milliseconds")
check(api.parse_utc("2026-10-22T19:29:30.000Z") == 1792697370.0, "parse_utc")
check(abs(api.parse_utc("2026-10-22T19:31:35.897Z") - 1792697495.897) < 1e-6, "parse_utc with ms")
check(api.parse_utc("garbage") is None and api.parse_utc(None) is None, "parse_utc rejects garbage")
q = api.device_query(api.parse_utc("2026-09-12T19:58:02.244Z"), 100)
check(q == "filter=lastConnectedDateTimeUtcFrom%20eq%20%272026-09-12T19%3A58%3A02.244Z%27&pageSize=100",
      "device filter query (same encoding as the earlier collector script)")
check(api.device_query(None, 0) == "", "no filter, API page size")

# ---- hosts
for host, ok in (("api.absolute.com", True), ("api.us.absolute.com", True), ("api.eu2.absolute.com", True),
                 ("evil.com", False), ("api.absolute.com.evil.com", False), ("api.absolute.com:443", False),
                 ("API.absolute.com", False)):
    check(bool(api.API_HOST_RE.match(host)) == ok, f"API host {host!r} {'accepted' if ok else 'refused'}")

# ---- client against the fake API
tmp = tempfile.mkdtemp(prefix="abs_unit_")
now = time.time()
events = fake.make_events(now - 3 * 3600, now - 60, per_minute=20)
srv = fake.FakeAbsolute(tmp, events, fake.make_devices(53, now))


class TestClient(api.Client):
    def base_url(self):
        return srv.url

    def make_ssl_context(self):
        ctx = api.ssl_context()
        ctx.load_verify_locations(srv.ca)
        return ctx


c = TestClient("api.absolute.com", fake.TOKEN_ID, fake.SECRET)
got = []
for records, page in api.siem_event_pages(c, now - 3 * 3600, now, 100):
    got += records
check(len(got) == len(events) and len({e["id"] for e in got}) == len(events), f"all {len(events)} events paged")
check(c.calls == -(-len(events) // 100), f"{c.calls} calls of 100")

srv.faults = [(429, {"Retry-After": "1"}, None), (503, None, None)]
c2 = TestClient("api.absolute.com", fake.TOKEN_ID, fake.SECRET)
c2._retry_wait = None
t0 = time.time()
doc = c2.get(api.SIEM_EVENTS, f"pageSize=1&fromDateTimeUtc={api.utc_text(now - 600)}&toDateTimeUtc={api.utc_text(now)}")
check(c2.retries == 2 and "data" in doc, f"429 (Retry-After) and 503 retried ({c2.retries} retries, {time.time() - t0:.0f} s)")

bad = TestClient("api.absolute.com", fake.TOKEN_ID, "wrong-secret")
try:
    bad.get(api.SIEM_EVENTS, "pageSize=1")
    check(False, "wrong secret refused")
except api.ApiError as exc:
    check(exc.status == 401 and "not accepted" in str(exc), f"wrong secret: {exc}")

srv.faults = [(403, None, {"message": "Forbidden"})]
try:
    c.get(api.DEVICES, "")
    check(False, "403 reported")
except api.ApiError as exc:
    check(exc.status == 403 and "IP address" in str(exc), "403 explains permission / IP allow list")


class NoCA(api.Client):
    def base_url(self):
        return srv.url


try:
    NoCA("api.absolute.com", fake.TOKEN_ID, fake.SECRET).get(api.DEVICES, "")
    check(False, "untrusted certificate refused")
except api.ApiError as exc:
    check("could not be verified" in str(exc), "untrusted TLS certificate refused with a clear message")

devs = []
for records, page in api.device_pages(c, now - 24 * 3600, 7):
    devs += records
expected = [d for d in srv.devices if api.parse_utc(d["lastConnectedDateTimeUtc"]) >= now - 24 * 3600]
check([d["esn"] for d in devs] == [d["esn"] for d in expected], f"devices filter + paging ({len(devs)} devices)")
all_devs = sum(len(r) for r, _ in api.device_pages(c, None, 0))
check(all_devs == 53, "every device with the API's default page size")
try:
    api.Client("evil.example.com", "x" * 10, "y")
    check(False, "non-Absolute host refused")
except api.ApiError:
    check(True, "non-Absolute host refused")
srv.close()
print("\nALL PASSED" if not FAILS else f"\n{len(FAILS)} failed")
sys.exit(1 if FAILS else 0)
