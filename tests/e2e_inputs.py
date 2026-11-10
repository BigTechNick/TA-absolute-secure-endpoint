#!/usr/bin/env python3
"""
e2e_inputs.py - runs both modular inputs as splunkd would (XML configuration on stdin,
XML events on stdout) against fake_absolute and the fake splunkd credential store.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(os.path.dirname(HERE), "TA-absolute-secure-endpoint")
BIN = os.path.join(APP, "bin")
sys.path[:0] = [os.path.join(HERE, "fake_splunk"), BIN, HERE]

home = tempfile.mkdtemp(prefix="abs_home_")
os.makedirs(os.path.join(home, "var", "log", "splunk"))
shutil.copytree(APP, os.path.join(home, "etc", "apps", "TA-absolute-secure-endpoint"))
os.environ.update(SPLUNK_HOME=home, FAKE_SPLUNKD_STATE=os.path.join(home, "splunkd.json"), FAKE_APP_BIN=BIN,
                  PYTHONPATH=os.path.join(HERE, "fake_splunk"))
import absolute_se_api as api  # noqa: E402
import absolute_se_store as store  # noqa: E402
import fake_absolute as fake  # noqa: E402

FAILS = []


def check(cond, label):
    print(("PASS  " if cond else "FAIL  ") + label)
    if not cond:
        FAILS.append(label)


NOW = time.time()
events = fake.make_events(NOW - 6 * 3600, NOW + 600, per_minute=12)
srv = fake.FakeAbsolute(home, events, fake.make_devices(60, NOW))
os.environ.update(FAKE_ABSOLUTE_URL=srv.url, FAKE_ABSOLUTE_CA=srv.ca)
accounts = store.Accounts(store.Splunkd("admin-key"))
accounts.save("absolute-test", {"api_host": "api.absolute.com", "token_id": fake.TOKEN_ID, "token_secret": fake.SECRET})
accounts.save("bad-secret", {"api_host": "api.absolute.com", "token_id": fake.TOKEN_ID, "token_secret": "nope"})
CKPT = os.path.join(home, "var", "lib", "splunk", "modinputs")


def run(scheme, name, params, timeout=180):
    items = "".join(f'<param name="{escape(k)}">{escape(str(v))}</param>' for k, v in params.items())
    xml = (f"<input><server_host>hf</server_host><server_uri>https://127.0.0.1:8089</server_uri>"
           f"<session_key>system-key</session_key><checkpoint_dir>{CKPT}/{scheme}</checkpoint_dir>"
           f'<configuration><stanza name="{scheme}://{name}">{items}</stanza></configuration></input>')
    res = subprocess.run([sys.executable, os.path.join(HERE, "run_input.py"), os.path.join(BIN, scheme + ".py")],
                         input=xml.encode(), capture_output=True, timeout=timeout)
    out = []
    text = res.stdout.decode("utf-8")
    if text.strip():
        root = ET.fromstring(text)
        for ev in root.iter("event"):
            out.append({"time": float(ev.findtext("time")), "host": ev.findtext("host"),
                        "sourcetype": ev.findtext("sourcetype"), "data": json.loads(ev.findtext("data"))})
    return res.returncode, out, res.stderr.decode()


def log_of(kind, name):
    try:
        return open(store.log_path(kind, name), encoding="utf-8").read()
    except OSError:
        return ""


def created(e):
    return api.parse_utc(e["createdDateTimeUtc"])


def expected(start, end):
    return {e["id"] for e in events if start <= created(e) <= end}


# ---------------------------------------------------------------- SIEM events
P = {"account": "absolute-test", "start_hours_ago": "2", "delay_minutes": "5", "overlap_minutes": "10",
     "page_size": "50", "log_level": "INFO", "interval": "300", "index": "endpoint"}

t0 = time.time()
rc, out1, err = run("absolute_events", "ev1", P)
state = json.load(open(os.path.join(CKPT, "absolute_events", "ev1.json")))
first_end = int(api.parse_utc(state["end"]))       # the run's own "now - delay"
check(abs(first_end - (int(t0) - 300)) <= 3, "checkpoint end = now - delay")
want = expected(first_end - 7200, first_end)
ids1 = [o["data"]["id"] for o in out1]
check(rc == 0, f"first run exits 0 {err[-300:]}")
check(set(ids1) == want and len(ids1) == len(want), f"first run: the {len(want)} events of the last 2 h (to now - 5 min)")
check(len(set(ids1)) == len(ids1), "first run: no duplicates")
check(all(o["sourcetype"] == "absolute:events" and o["host"] == "absolute-test" for o in out1),
      "sourcetype absolute:events, host = account name")
sample = next(o for o in out1 if o["data"]["eventType"] == "UserLogin")
check(sample["data"]["properties"]["IpAddress"]["new"] == "203.0.113.10" and
      "BrowserAgent" in sample["data"]["properties"], "objectProperties split into properties")
check(abs(sample["time"] - api.parse_utc(sample["data"]["eventDateTimeUtc"])) < 0.01,
      "_time = eventDateTimeUtc (not the time Absolute recorded it)")
blocked = next(o for o in out1 if o["data"]["eventType"] == "DeviceConnectionBlocked")
check(blocked["data"]["properties"].get("Reason", {}).get("new") == "Inside restricted region",
      "event type prefix removed from property names")
check(all(k in sample["data"] for k in ("id", "eventType", "objectProperties", "createdDateTimeUtc")),
      "Absolute's fields kept as they come")
check(0 < len(state["seen"]) and min(state["seen"].values()) >= first_end - 122 * 60 - 1,
      f"checkpoint keeps only the ids of the last 122 minutes ({len(state['seen'])})")
log1 = log_of("events", "ev1")
check("first run for account absolute-test" in log1 and "run done: written %d" % len(ids1) in log1, "run logged")
check(api.parse_utc(state["end"]) and "seen" in state, "checkpoint saved")

# Events Absolute records late (visible only after the next run) inside the overlap are still collected.
late = [e for e in events if first_end - 400 <= created(e) <= first_end - 60]
late_ids = {e["id"] for e in late}
for e in late:
    srv.visible[e["id"]] = time.time() + 3600
# (they were already sent in run 1, so hide them from run 1's results for this check: simulate as new ones)
fresh_late = [fake.event(first_end - 200 + i, "NewApplicationDetected", __import__("random").Random(i))
              for i in range(5)]
for e in fresh_late:
    srv.visible[e["id"]] = time.time() + 10
events.extend(fresh_late)
events.sort(key=lambda e: e["id"])
srv.events = events

time.sleep(2)
rc, out2, err = run("absolute_events", "ev1", P)
ids2 = [o["data"]["id"] for o in out2]
check(rc == 0, "second run exits 0")
check(not (set(ids2) & set(ids1)), f"second run: nothing sent twice ({len(ids2)} new)")
check(not ({e['id'] for e in fresh_late} & set(ids2)), "events not yet visible are not sent")
log2 = log_of("events", "ev1")
m = re.findall(r"run done: written (\d+), duplicates (\d+)", log2)
check(len(m) == 2 and int(m[-1][1]) > 0, f"overlap refetched and skipped by id (duplicates {m[-1][1] if m else '?'})")

time.sleep(11)                     # the late events become visible
for e in late:
    srv.visible.pop(e["id"], None)
rc, out3, err = run("absolute_events", "ev1", P)
ids3 = {o["data"]["id"] for o in out3}
check({e["id"] for e in fresh_late} <= ids3, "events Absolute recorded late (within the overlap) are collected")
check(not (ids3 & (set(ids1) | set(ids2))), "still nothing sent twice")

# Excluded event types; start from now (start_hours_ago = 0)
rc, out, err = run("absolute_events", "ev-ex", dict(P, start_hours_ago="1", exclude_event_types="ApplicationUninstalled,NewApplicationDetected"))
types = {o["data"]["eventType"] for o in out}
check(rc == 0 and out and not types & {"ApplicationUninstalled", "NewApplicationDetected"}, "exclude_event_types")
check(re.search(r"excluded [1-9]\d*", log_of("events", "ev-ex")) is not None, "excluded count logged")
rc, out, err = run("absolute_events", "ev-now", dict(P, start_hours_ago="0"))
check(rc == 0 and not out and os.path.exists(os.path.join(CKPT, "absolute_events", "ev-now.json")),
      "start_hours_ago = 0: first run sends nothing and starts the checkpoint at now")

# Rate limit and server errors are retried
srv.faults = [(429, {"Retry-After": "1"}, None), (502, None, None)]
rc, out, err = run("absolute_events", "ev-retry", dict(P, start_hours_ago="1"))
check(rc == 0 and len(out) > 0, "429 and 502 retried, run completes")
check("retry 1 of 5" in log_of("events", "ev-retry"), "retries logged")

# A failure in the second window: the first window's checkpoint stays, the next run continues without gaps
srv.faults = []
P3 = dict(P, start_hours_ago="3", page_size="1000")
# Let the first window succeed (one page), then fail every retry of the second window.
orig_handle = srv.handle
count = {"n": 0}


def flaky(jws):
    count["n"] += 1
    if count["n"] >= 2 and count["n"] <= 7:
        return 503, {"message": "server error"}, {"Retry-After": "1"}
    return orig_handle(jws)


srv.handle = flaky
t_run = time.time()
rc, outa, err = run("absolute_events", "ev-gap", P3, timeout=400)
srv.handle = orig_handle
st = json.load(open(os.path.join(CKPT, "absolute_events", "ev-gap.json")))
check(rc == 1 and "run failed" in log_of("events", "ev-gap"), "a window that keeps failing ends the run as failed")
check(abs(api.parse_utc(st["end"]) - (int(t_run) - 300 - 3 * 3600 + 3600)) <= 2,
      "checkpoint stays at the end of the last complete window")
rc, outb, err = run("absolute_events", "ev-gap", P3)
got = [o["data"]["id"] for o in outa + outb]
want = expected(int(t_run) - 300 - 3 * 3600, int(time.time()) - 300 - 2)
check(rc == 0 and want <= set(got), f"next run continues: no gap ({len(want - set(got))} missing)")
check(len(got) == len(set(got)), "and no duplicates")

# A window cut short after some of its pages were sent: the next run sends neither them again nor leaves a gap
P4 = dict(P, start_hours_ago="1", page_size="50")
count["n"] = 0


def flaky_mid(jws):
    count["n"] += 1
    if 3 <= count["n"] <= 8:                  # pages 1-2 of the first window go out, then every retry fails
        return 503, {"message": "server error"}, {"Retry-After": "1"}
    return orig_handle(jws)


srv.handle = flaky_mid
t_run = time.time()
rc, outa, err = run("absolute_events", "ev-mid", P4)
srv.handle = orig_handle
st = json.load(open(os.path.join(CKPT, "absolute_events", "ev-mid.json")))
check(rc == 1 and len(outa) == 100 and st.get("end") is None and len(st["seen"]) == 100,
      f"window cut short: {len(outa)} events sent, their ids saved, no window end yet")
rc, outb, err = run("absolute_events", "ev-mid", P4)
got = [o["data"]["id"] for o in outa + outb]
want = expected(int(t_run) - 300 - 3600, int(time.time()) - 300 - 2)
check(rc == 0 and len(got) == len(set(got)), f"next run: nothing sent twice ({len(got)} events)")
check(want <= set(got), f"next run: no gap ({len(want - set(got))} missing)")

# Wrong secret
rc, out, err = run("absolute_events", "ev-bad", dict(P, account="bad-secret"))
check(rc == 1 and not out and "not accepted" in log_of("events", "ev-bad"), "wrong secret: run failed, logged")
check(not os.path.exists(os.path.join(CKPT, "absolute_events", "ev-bad.json")), "no checkpoint written on failure")
rc, out, err = run("absolute_events", "ev-noacct", dict(P, account="missing"))
check(rc == 1 and "is not saved" in log_of("events", "ev-noacct"), "unknown account: run failed, logged")
rc, out, err = run("absolute_events", "bad name!", P)
check(rc == 1 and "Input name" in err, "invalid settings refused at start (stderr -> splunkd.log)")

# ---------------------------------------------------------------- devices
D = {"account": "absolute-test", "connected_within_hours": "24", "page_size": "7", "exclude_fields": "printers,usbs",
     "log_level": "INFO", "interval": "86400", "index": "endpoint"}
rc, devs, err = run("absolute_devices", "dev1", D)
want = [d for d in srv.devices if api.parse_utc(d["lastConnectedDateTimeUtc"]) >= NOW - 24 * 3600 - 60]
check(rc == 0 and len(devs) == len(want), f"devices connected in 24 h: {len(devs)} of {len(srv.devices)}")
check(all(o["sourcetype"] == "absolute:devices" and o["host"] == "absolute-test" for o in devs), "sourcetype, host")
check(len({o["time"] for o in devs}) == 1, "one _time for the whole snapshot")
keys = list(devs[0]["data"].keys())
check(keys[:2] == ["deviceUid", "deviceName"] and keys.index("operatingSystem") < keys.index("totalPhysicalRamBytes")
      < keys.index("networkAdapters"), "summary fields first")
check(all("printers" not in o["data"] and "usbs" not in o["data"] for o in devs), "exclude_fields left out")
src0 = next(d for d in srv.devices if d["deviceUid"] == devs[0]["data"]["deviceUid"])
check(sorted(devs[0]["data"]) == sorted(k for k in src0 if k not in ("printers", "usbs")), "other fields kept")
src = next(d for d in srv.devices if d["deviceUid"] == devs[0]["data"]["deviceUid"])
check(all(devs[0]["data"][k] == src[k] for k in devs[0]["data"]), "values unchanged")
log = log_of("devices", "dev1")
check("run done: devices %d, pages %d" % (len(devs), -(-len(devs) // 7)) in log, "run logged with pages")

rc, again, err = run("absolute_devices", "dev1", D)
check(rc == 0 and not again and "run skipped" in log_of("devices", "dev1"), "a run soon after the last one is skipped")
marker = store.run_now_path("absolute_devices", "dev1", os.path.join(CKPT, "absolute_devices"))
open(marker, "w").write("now")
rc, forced, err = run("absolute_devices", "dev1", D)
check(rc == 0 and len(forced) == len(devs) and not os.path.exists(marker), "Run now runs it anyway")
rc, alldevs, err = run("absolute_devices", "dev-all", dict(D, connected_within_hours="0", page_size="0", exclude_fields=""))
check(rc == 0 and len(alldevs) == len(srv.devices) and "printers" in alldevs[0]["data"],
      "connected_within_hours = 0: every device (API default page size)")
srv.max_devices_page = 50
rc, out, err = run("absolute_devices", "dev-big", dict(D, page_size="100"))
check(rc == 1 and "pageSize" in log_of("devices", "dev-big") and "run failed" in log_of("devices", "dev-big"),
      "API error (page size refused) logged as run failed")
st = os.path.join(CKPT, "absolute_devices", "dev-big.json")
check(not os.path.exists(st), "failed run is not recorded as complete (the next one runs)")

# ---------------------------------------------------------------- status from the log
s = store.read_status("events", "ev1")
check(s.get("result") == "done" and s.get("count") is not None and "behind" in s, f"read_status events {s}")
s = store.read_status("devices", "dev-big")
check(s.get("result") == "failed" and "pageSize" in (s.get("last_error") or ""), "read_status shows a failed run")
s = store.read_status("devices", "dev1")
check(s.get("result") == "done" and s.get("count") == str(len(devs)), "read_status devices count")

srv.close()
print("\nALL PASSED" if not FAILS else f"\n{len(FAILS)} failed")
sys.exit(1 if FAILS else 0)
