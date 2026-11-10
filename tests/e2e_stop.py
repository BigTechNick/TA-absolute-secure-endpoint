#!/usr/bin/env python3
"""
e2e_stop.py - runs that Splunk stops part-way, as splunkd does when an input is disabled, edited or
restarted (Run now): splunkd closes the pipe it reads events from, or sends SIGTERM. Checks that the
run ends cleanly ("run stopped", exit 0, no traceback), that no event is lost, and that events are
indexed twice only when the pipe was closed (events on their way may not have arrived).
"""
import fcntl
import json
import os
import re
import shutil
import signal
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

home = tempfile.mkdtemp(prefix="abs_stop_")
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
store.Accounts(store.Splunkd("admin-key")).save(
    "absolute-test", {"api_host": "api.absolute.com", "token_id": fake.TOKEN_ID, "token_secret": fake.SECRET})
CKPT = os.path.join(home, "var", "lib", "splunk", "modinputs")
EVENT_RE = re.compile(rb"<event>.*?</event>", re.S)


def config(scheme, name, params):
    items = "".join(f'<param name="{escape(k)}">{escape(str(v))}</param>' for k, v in params.items())
    return (f"<input><server_host>hf</server_host><server_uri>https://127.0.0.1:8089</server_uri>"
            f"<session_key>system-key</session_key><checkpoint_dir>{CKPT}/{scheme}</checkpoint_dir>"
            f'<configuration><stanza name="{scheme}://{name}">{items}</stanza></configuration></input>').encode()


def parse(data):
    out = []
    for chunk in EVENT_RE.findall(data):
        ev = ET.fromstring(chunk)
        out.append(json.loads(ev.findtext("data")))
    return out


def start(scheme, name, params):
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "run_input.py"), os.path.join(BIN, scheme + ".py")],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdin.write(config(scheme, name, params))
    proc.stdin.close()
    return proc


def read_until(proc, n_events, timeout=60, complete_only=True):
    """Reads stdout like splunkd until n_events complete events have arrived."""
    data, end = b"", time.time() + timeout
    while data.count(b"</event>") < n_events and time.time() < end:
        chunk = os.read(proc.stdout.fileno(), 4096)
        if not chunk:
            break
        data += chunk
    if not complete_only:
        return data
    # keep only complete events: what splunkd had received when it stopped reading
    last = data.rfind(b"</event>")
    return data[:last + len(b"</event>")] if last >= 0 else b""


def run(scheme, name, params, timeout=300):
    res = subprocess.run([sys.executable, os.path.join(HERE, "run_input.py"), os.path.join(BIN, scheme + ".py")],
                         input=config(scheme, name, params), capture_output=True, timeout=timeout)
    return res.returncode, parse(res.stdout), res.stderr.decode()


def log_of(kind, name):
    try:
        return open(store.log_path(kind, name), encoding="utf-8").read()
    except OSError:
        return ""


def created(e):
    return api.parse_utc(e["createdDateTimeUtc"])


def expected(lo, hi):
    return {e["id"] for e in events if lo <= created(e) <= hi}


def run_start(kind, name):
    """Where the input's first run started, from its log (the run's own clock, not the test's)."""
    return api.parse_utc(re.search(r"collecting from (\S+)", log_of(kind, name)).group(1))


def state_of(scheme, name):
    try:
        return json.load(open(os.path.join(CKPT, scheme, name + ".json")))
    except OSError:
        return None


P = {"account": "absolute-test", "start_hours_ago": "3", "delay_minutes": "5", "overlap_minutes": "10",
     "page_size": "50", "log_level": "INFO", "interval": "300", "index": "endpoint"}

# ------------------------------------------------- 1. splunkd closes the pipe in the second window
t_run = time.time()
proc = start("absolute_events", "cut", P)
got1 = parse(read_until(proc, 1000))                 # window 1 has ~720 events: this is inside window 2
proc.stdout.close()                                  # splunkd stops reading (input disabled / Run now)
rc = proc.wait(timeout=120)
err = proc.stderr.read().decode()
log = log_of("events", "cut")
check(rc == 0, f"pipe closed: the run exits 0 (rc {rc})")
check("Traceback" not in err and "Exception ignored" not in err and "BrokenPipe" not in err,
      f"pipe closed: no traceback on stderr (splunkd.log) {err[-300:]}")
check("run stopped: Splunk stopped reading" in log and "run failed" not in log, "pipe closed: logged as run stopped")
check(store.read_status("events", "cut").get("result") == "stopped", "pipe closed: status shows the run stopped")
st = state_of("absolute_events", "cut")
first_window_end = run_start("events", "cut") + 3600
check(st and abs(api.parse_utc(st["end"]) - first_window_end) <= 3,
      "pipe closed: checkpoint stays at the end of the first (complete) window")
cut_ids = {e["id"] for e in got1 if created(e) > api.parse_utc(st["end"])}
check(cut_ids and not cut_ids & set(st["seen"]), "pipe closed: ids of the cut-short window are not kept as sent")
rc, got2, err = run("absolute_events", "cut", P)
ids1, ids2 = [e["id"] for e in got1], [e["id"] for e in got2]
want = expected(run_start("events", "cut"), api.parse_utc(state_of("absolute_events", "cut")["end"]))
check(rc == 0 and want <= set(ids1) | set(ids2), f"pipe closed: next run, no event lost ({len(want - set(ids1) - set(ids2))} missing)")
twice = set(ids1) & set(ids2)
check(len(ids2) == len(set(ids2)), "pipe closed: next run sends each event once")
check(twice and all(created(e) > first_window_end - 600 for e in got1 if e["id"] in twice),
      f"pipe closed: only the cut-short window is sent again ({len(twice)} events twice)")

# ------------------------------------------------- 2. SIGTERM in the second window (pipe still open)
t_run = time.time()
proc = start("absolute_events", "term", P)
data = read_until(proc, 1000, complete_only=False)
proc.send_signal(signal.SIGTERM)                     # splunkd stopping the input
rest, _ = proc.communicate(timeout=120)              # splunkd keeps reading until the input exits
got1 = parse(data + rest)
rc = proc.returncode
log = log_of("events", "term")
check(rc == 0 and "run stopped: stopped by Splunk" in log and "run done" not in log, "SIGTERM: logged as run stopped, exit 0")
st = state_of("absolute_events", "term")
check(st and {e["id"] for e in got1 if created(e) > api.parse_utc(st["end"])} <= set(st["seen"]),
      "SIGTERM: the ids sent from the cut-short window are kept")
rc, got2, err = run("absolute_events", "term", P)
ids1, ids2 = [e["id"] for e in got1], [e["id"] for e in got2]
want = expected(run_start("events", "term"), api.parse_utc(state_of("absolute_events", "term")["end"]))
check(rc == 0 and want <= set(ids1) | set(ids2), f"SIGTERM: next run, no event lost ({len(want - set(ids1) - set(ids2))} missing)")
check(not set(ids1) & set(ids2) and len(ids1) == len(set(ids1)), "SIGTERM: nothing sent twice")

# ------------------------------------------------- 3. pipe closed in the first window of a first run
P1 = dict(P, start_hours_ago="1")
t_run = time.time()
proc = start("absolute_events", "first", P1)
got1 = parse(read_until(proc, 200))
proc.stdout.close()
rc = proc.wait(timeout=120)
st = state_of("absolute_events", "first")
check(rc == 0 and st and st.get("end") is None and st.get("start") and not st["seen"],
      "first window cut: no window end, the first run's start saved, no ids kept")
first_start = api.parse_utc(st["start"])
check(abs(first_start - (int(t_run) - 300 - 3600)) <= 3, "first window cut: start = the first run's start")
time.sleep(2)
rc, got2, err = run("absolute_events", "first", P1)
want = expected(first_start, api.parse_utc(state_of("absolute_events", "first")["end"]))
got = {e["id"] for e in got1} | {e["id"] for e in got2}
check(rc == 0 and "continuing from" in log_of("events", "first") and want <= got,
      f"first window cut: next run starts at the same point, no event lost ({len(want - got)} missing)")

# ------------------------------------------------- 4. devices: pipe closed part-way
D = {"account": "absolute-test", "connected_within_hours": "0", "page_size": "7", "log_level": "INFO",
     "interval": "86400", "index": "endpoint"}
proc = start("absolute_devices", "devcut", D)
read_until(proc, 3)
proc.stdout.close()
rc = proc.wait(timeout=120)
err = proc.stderr.read().decode()
log = log_of("devices", "devcut")
check(rc == 0 and "run stopped: Splunk stopped reading" in log and "Traceback" not in err,
      f"devices, pipe closed: run stopped, exit 0, no traceback {err[-200:]}")
check(state_of("absolute_devices", "devcut") is None, "devices, pipe closed: not recorded as complete")
rc, devs, err = run("absolute_devices", "devcut", D)
check(rc == 0 and len(devs) == len(srv.devices), "devices, pipe closed: the next run is not skipped and sends all")

# ------------------------------------------------- 5. a run in progress holds the lock
lock = store.lock_path("absolute_events", "busy", os.path.join(CKPT, "absolute_events"))
os.makedirs(os.path.dirname(lock), exist_ok=True)
fh = open(lock, "w")
fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
check(store.run_in_progress("absolute_events", "busy", os.path.join(CKPT, "absolute_events")),
      "run_in_progress while the lock is held")
rc, out, err = run("absolute_events", "busy", P1)
check(rc == 0 and not out and "run skipped: the previous run" in log_of("events", "busy"), "a second run is skipped")
fcntl.flock(fh, fcntl.LOCK_UN)
fh.close()
check(not store.run_in_progress("absolute_events", "busy", os.path.join(CKPT, "absolute_events")),
      "not in progress once released")

srv.close()
print("\nALL PASSED" if not FAILS else f"\n{len(FAILS)} failed")
sys.exit(1 if FAILS else 0)
