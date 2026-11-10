"""
fake_absolute.py - a stand-in for the Absolute API, for tests.

HTTPS server for POST /jws/validate: checks the JWS (HS256 with the test token's
secret, kid, issuedAt within 5 minutes, payload {"data":{}}), then serves:
  * /v3/reporting/siem-events: pageSize (1-1000), fromDateTimeUtc/toDateTimeUtc on
    createdDateTimeUtc, sorted by id, nextPage = the last id of the page.
    Events can be made visible late (visible_at) to test the delay and overlap.
  * /v3/reporting/devices-advanced: filter=lastConnectedDateTimeUtcFrom eq '<ts>',
    pageSize (default 10), keyset paging on esn with a base64 nextPage like Absolute's.
Faults: queue (status, headers, body) answers for the next calls.
All data is synthetic (documentation IP ranges, example.com users).
"""
import base64
import calendar
import hashlib
import hmac
import http.server
import json
import os
import random
import re
import ssl
import subprocess
import threading
import time
import urllib.parse

TOKEN_ID = "11111111-2222-3333-4444-555555555555"
SECRET = "dGVzdC1zZWNyZXQta2V5LWZvci1mYWtlLWFic29sdXRlLWFwaS0wMTIzNDU2Nzg5"


def iso(epoch, ms=True):
    whole = int(epoch)
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(whole))
    return base + (".%03dZ" % int((epoch - whole) * 1000) if ms else ".000Z")


def parse_iso(text):
    m = re.match(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?Z$", text or "")
    if not m:
        raise ValueError(text)
    g = [int(x) for x in m.groups()[:6]]
    return calendar.timegm((g[0], g[1], g[2], g[3], g[4], g[5], 0, 0, 0)) + float("0." + (m.group(7) or "0"))


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def make_cert(folder):
    key, cert = os.path.join(folder, "server.key"), os.path.join(folder, "server.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                    "-days", "2", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                   check=True, capture_output=True)
    return cert, key


# ---------------------------------------------------------------- data

_counter = [0]


def object_id(created):
    _counter[0] += 1
    return "%08x%016x" % (int(created), _counter[0])


def props(*triples, indexed=True):
    if len(triples) == 1 and not indexed:
        n, o, v = triples[0]
        return f"PropertyName={n};OldValue={o};NewValue={v};"
    return "".join(f"PropertyName[{i}]={n};OldValue[{i}]={o};NewValue[{i}]={v};"
                   for i, (n, o, v) in enumerate(triples, 1))


DEVICES = [f"LAB-{i:04d}" for i in range(1, 41)] + ["Λάπτοπ-01"]
USERS = ["admin1@example.com", "analyst2@example.com"]


def event(created, kind, rnd, event_lag=None):
    dev = rnd.choice(DEVICES)
    dev_id = hashlib.md5(dev.encode()).hexdigest()
    dev_uid = f"{dev_id[:8]}-{dev_id[8:12]}-{dev_id[12:16]}-{dev_id[16:20]}-{dev_id[20:32]}"
    happened = created - (event_lag if event_lag is not None else rnd.uniform(5, 3000))
    rec = {"id": object_id(created), "eventType": kind, "actorObjectType": "Device", "actorDisplayName": dev,
           "actorDisplayId": dev_uid, "objectObjectType": "Device", "objectDisplayName": dev,
           "objectDisplayId": dev_uid, "objectProperties": "", "verb": "Updated"}
    if kind == "NewApplicationDetected":
        rec.update(objectObjectType="Application", objectDisplayName="Example Notes 1.2.3 Example Corp",
                   objectDisplayId="aaaa1111-0000-3000-8000-000000000001", verb="Installed",
                   objectProperties=props(("ApplicationName", "", "Example Notes"), ("ApplicationVersion", "", "1.2.3"),
                                          ("ApplicationPublisher", "", "Example Corp")))
    elif kind == "ApplicationUninstalled":
        rec.update(objectObjectType="Application", objectDisplayName="Old Tool 0.9 Example Corp",
                   objectDisplayId="aaaa1111-0000-3000-8000-000000000002", verb="Uninstalled",
                   objectProperties=props(("ApplicationName", "", "Old Tool"), ("ApplicationVersion", "", "0.9"),
                                          ("ApplicationPublisher", "", "Example Corp")))
    elif kind == "DeviceSystemInformationUpdated":
        rec.update(objectProperties=props(("DeviceSystemInformationUpdated.PublicIpAddr", "198.51.100.7",
                                           "198.51.100.9"), indexed=False))
    elif kind == "DeviceLocationUpdated":
        rec.update(objectObjectType="Geolocation", objectDisplayName="Device Location",
                   objectProperties=props(("Longitude", "12.5", "12.6"), ("Latitude", "45.5", "45.6"),
                                          ("City", "Springfield", "Shelbyville"), ("Gps.ErrorKey", "",
                                                                                  "com.example.gps")))
    elif kind == "DeviceVolumeAdded":
        rec.update(verb="Added", secondaryObjectType="Volume", secondaryObjectDisplayName="D:\\",
                   secondaryObjectDisplayId="\\\\?\\Volume{0000-1111}\\")
    elif kind == "DeviceCDCValueUpdated":
        long_value = ", ".join(f"Extension {i} 1.{i}" for i in range(200))
        rec.update(objectObjectType="CDC", objectDisplayName="sys_extensions",
                   objectProperties=props(("Value", long_value, long_value + "; Extra 2.0"), indexed=False))
    elif kind == "UserLogin":
        user = rnd.choice(USERS)
        rec.update(actorObjectType="User", actorDisplayName=user, actorDisplayId="u-" + user.split("@")[0],
                   objectObjectType="IdentityProvider", objectDisplayName="Absolute IDP",
                   objectDisplayId="Absolute IDP", verb="LoggedIn",
                   objectProperties=props(("IpAddress", "", "203.0.113.10"),
                                          ("BrowserAgent", "", "Mozilla/5.0 (X11; Linux x86_64) Test/1.0")))
    elif kind == "UserUpdated":
        rec.update(actorObjectType="User", actorDisplayName=USERS[0], actorDisplayId="u-admin1",
                   objectObjectType="User", objectDisplayName=USERS[1], objectDisplayId="u-analyst2",
                   objectProperties=props(("Role", "Power User", "Security Administrator"), indexed=False))
    elif kind == "RuleUpdated":
        rec.update(actorObjectType="User", actorDisplayName=USERS[0], actorDisplayId="u-admin1",
                   objectObjectType="Rule", objectDisplayName="Device leaves the country",
                   objectDisplayId="r-1", objectProperties=props(("description", "", "test; with semicolon"),
                                                                  indexed=False))
    elif kind == "DeviceFrozen":
        rec.update(actorObjectType="User", actorDisplayName=USERS[0], actorDisplayId="u-admin1", verb="Frozen",
                   secondaryObjectType="Request", secondaryObjectDisplayName="DeviceFreeze-1",
                   secondaryObjectDisplayId="req-1")
    elif kind == "LocationHistoryAccessed":
        rec.update(actorObjectType="User", actorDisplayName=USERS[1], actorDisplayId="u-analyst2", verb="Accessed")
    elif kind == "AlertTriggered":
        rec.update(actorObjectType="RuleDefinition", actorDisplayName="Device outside the country",
                   actorDisplayId="rule-1", objectObjectType="Event", objectDisplayName="DeviceExitedItsGeofence",
                   objectDisplayId="ev-1", verb="Triggered", secondaryObjectType="Device",
                   secondaryObjectDisplayName=dev, secondaryObjectDisplayId=dev_uid)
    elif kind == "DeviceConnectionBlocked":
        rec.update(actorObjectType="System", actorDisplayName="System", verb="Blocked",
                   secondaryObjectType="Region", secondaryObjectDisplayName="Exampleland", secondaryObjectDisplayId="XL",
                   objectProperties=props(("DeviceConnectionBlocked.Reason", "", "Inside restricted region"),
                                          ("DeviceConnectionBlocked.RestrictedRegion", "", "Exampleland")))
    elif kind == "AgentSelfHealingCall":
        rec.update(actorDisplayName="", objectObjectType="", objectDisplayName="", objectDisplayId="",
                   verb="Self-Healed")
    rec["createdDateTimeUtc"] = iso(created)
    rec["eventDateTimeUtc"] = iso(happened, ms=False)
    return rec


KINDS = ["NewApplicationDetected"] * 6 + ["ApplicationUninstalled"] * 5 + ["DeviceSystemInformationUpdated"] * 4 + \
    ["DeviceLocationUpdated"] * 2 + ["DeviceVolumeAdded", "DeviceCDCValueUpdated", "UserLogin", "UserUpdated",
                                    "RuleUpdated", "DeviceFrozen", "LocationHistoryAccessed", "AlertTriggered",
                                    "DeviceConnectionBlocked", "AgentSelfHealingCall"]


def make_events(start, end, per_minute, seed=1):
    rnd = random.Random(seed)
    out = []
    t = start
    step = 60.0 / per_minute
    while t < end:
        out.append(event(t + rnd.uniform(0, step), rnd.choice(KINDS), rnd))
        t += step
    out.sort(key=lambda e: e["id"])
    return out


def make_devices(n, now, seed=2):
    rnd = random.Random(seed)
    devs = []
    for i in range(n):
        name = f"LAB-{i:04d}"
        recent = i % 4 != 0                       # every 4th device last connected long ago
        last = now - (rnd.uniform(60, 20 * 3600) if recent else rnd.uniform(40 * 86400, 900 * 86400))
        devs.append({
            "deviceUid": f"00000000-0000-4000-8000-{i:012d}", "esn": f"ESN{i:017d}",
            "accountUid": "00000000-0000-0000-0000-00000000acc1", "lastUpdatedDateTimeUtc": iso(last),
            "agentStatus": "A" if recent else "D", "platformOSType": "Windows", "deviceName": name,
            "systemManufacturer": "Example Inc.", "systemModel": "Book 14", "serialNumber": f"SN{i:06d}",
            "username": f"EXAMPLE\\user{i}", "currentUsername": f"EXAMPLE\\user{i}",
            "totalPhysicalRamBytes": 17179869184 if i % 5 else 16304,
            "printers": [{"id": f"Printer {k}", "name": f"Printer {k}", "driver": "Generic"} for k in range(5)],
            "usbs": [{"id": f"USB\\VID_{k:04d}", "name": f"USB controller {k}"} for k in range(4)],
            "localIp": f"192.0.2.{i % 250 + 1}", "publicIp": "198.51.100.20",
            "firstCallDateTimeUtc": iso(now - 1000 * 86400), "lastConnectedDateTimeUtc": iso(last),
            "cpu": {"id": "CPU0", "name": "Example CPU @ 3.0GHz", "architecture": "9", "physicalCores": 4,
                    "logicalCores": 8, "processorSpeed": 3000},
            "networkAdapters": [{"id": "1", "name": "Example Ethernet", "ipV4Address": f"192.0.2.{i % 250 + 1}",
                                 "macAddress": "0xB8CA3A9B%04X" % i},
                                {"id": "2", "name": "Example Wi-Fi", "macAddress": "B8:CA:3A:9B:04:%02X" % (i % 256)}],
            "operatingSystem": {"name": "Microsoft Windows 11 Enterprise", "version": "10.0.26100", "build": "26100"},
            "volumes": [{"id": "1", "name": "C:\\", "driveLetter": "C:", "sizeBytes": 256000000000}],
            "espInfo": {"encryptionStatus": "USENCR", "encryptionProductName": "Example Encryption"},
            "avpInfo": {"antivirusName": "Example AV"},
        })
    devs.sort(key=lambda d: d["esn"])
    return devs


# ---------------------------------------------------------------- server

class FakeAbsolute:
    def __init__(self, folder, events=None, devices=None):
        self.events = events or []
        self.devices = devices or []
        self.calls = []
        self.faults = []                  # (status, headers, body) for the next calls
        self.visible = {}                 # event id -> epoch it becomes visible
        self.to_inclusive = True          # toDateTimeUtc includes the boundary (worst case for duplicates)
        self.max_devices_page = 1000
        self.lock = threading.Lock()
        cert, key = make_cert(folder)
        self.ca = cert
        srv = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def answer(self, status, doc, headers=None):
                data = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                if self.path != "/jws/validate":
                    return self.answer(404, {"message": "not found"})
                if self.headers.get("Content-Type") != "text/plain":
                    return self.answer(415, {"message": "content type"})
                status, doc, headers = srv.handle(body)
                self.answer(status, doc, headers)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()

    def handle(self, jws):
        try:
            h64, p64, s64 = jws.split(".")
            header = json.loads(b64d(h64))
            payload = json.loads(b64d(p64))
        except Exception:
            return 400, {"message": "malformed JWS"}, None
        expected = hmac.new(SECRET.encode(), f"{h64}.{p64}".encode(), hashlib.sha256).digest()
        if header.get("kid") != TOKEN_ID or not hmac.compare_digest(expected, b64d(s64)):
            return 401, {"message": "Invalid token"}, None
        if header.get("alg") != "HS256" or header.get("method") != "GET" or payload != {"data": {}}:
            return 400, {"message": "bad request header"}, None
        if abs(time.time() * 1000 - int(header.get("issuedAt", 0))) > 300000:
            return 401, {"message": "issuedAt too old"}, None
        uri, query = header.get("uri"), header.get("query-string", "")
        with self.lock:
            self.calls.append((uri, query))
            if self.faults:
                status, headers, body = self.faults.pop(0)
                return status, body or {"message": "fault"}, headers
        params = {}
        for part in query.split("&") if query else []:
            key, _, value = part.partition("=")
            # nextPage is used as sent (Absolute's tokens are base64 and are sent unencoded)
            params[key] = value if key == "nextPage" else urllib.parse.unquote_plus(value)
        if uri == "/v3/reporting/siem-events":
            return self.siem(params)
        if uri == "/v3/reporting/devices-advanced":
            return self.devs(params)
        return 404, {"message": f"no resource {uri}"}, None

    def siem(self, params):
        try:
            size = int(params["pageSize"])
            start, end = parse_iso(params["fromDateTimeUtc"]), parse_iso(params["toDateTimeUtc"])
        except (KeyError, ValueError) as exc:
            return 400, {"message": f"bad parameters {exc}"}, None
        if not 1 <= size <= 1000:
            return 400, {"message": "pageSize must be 1-1000"}, None
        after = params.get("nextPage", "")
        now = time.time()
        rows = []
        for e in self.events:
            created = parse_iso(e["createdDateTimeUtc"])
            if created < start or created > end or (created == end and not self.to_inclusive):
                continue
            if self.visible.get(e["id"], 0) > now or e["id"] <= after:
                continue
            rows.append(e)
        page = rows[:size]
        doc = {"data": page, "metadata": {"pagination": {}}}
        if len(rows) > size:
            doc["metadata"]["pagination"]["nextPage"] = page[-1]["id"]
        return 200, doc, None

    def devs(self, params):
        size = int(params.get("pageSize") or 10)
        if not 1 <= size <= self.max_devices_page:
            return 400, {"message": "pageSize out of range"}, None
        rows = self.devices
        flt = params.get("filter")
        if flt:
            m = re.match(r"^lastConnectedDateTimeUtcFrom eq '(.+)'$", flt)
            if not m:
                return 400, {"message": f"bad filter {flt}"}, None
            since = parse_iso(m.group(1))
            rows = [d for d in rows if parse_iso(d["lastConnectedDateTimeUtc"]) >= since]
        token = params.get("nextPage")
        if token:
            m = re.match(r"^\$filter=\(\(esn gt '(.+)'\)\)&\$orderby=esn asc$", base64.b64decode(token).decode())
            rows = [d for d in rows if d["esn"] > m.group(1)]
        page = rows[:size]
        doc = {"data": page, "metadata": {"pagination": {}}}
        if len(rows) > size:
            last = page[-1]["esn"]
            doc["metadata"]["pagination"]["nextPage"] = base64.b64encode(
                f"$filter=((esn gt '{last}'))&$orderby=esn asc".encode()).decode()
        return 200, doc, None
