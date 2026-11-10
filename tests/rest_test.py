#!/usr/bin/env python3
"""rest_test.py - the Inputs page's REST API (absolute_se_rest.Handler) against the fake splunkd and fake_absolute."""
import json
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(os.path.dirname(HERE), "TA-absolute-secure-endpoint")
BIN = os.path.join(APP, "bin")
sys.path[:0] = [os.path.join(HERE, "fake_splunk"), BIN, HERE]
home = tempfile.mkdtemp(prefix="abs_rest_")
os.makedirs(os.path.join(home, "var", "log", "splunk"))
shutil.copytree(APP, os.path.join(home, "etc", "apps", "TA-absolute-secure-endpoint"))
os.environ.update(SPLUNK_HOME=home, FAKE_SPLUNKD_STATE=os.path.join(home, "splunkd.json"), FAKE_APP_BIN=BIN,
                  PYTHONPATH=os.path.join(HERE, "fake_splunk"))
import absolute_se_api as api  # noqa: E402
import absolute_se_rest as rest  # noqa: E402
import absolute_se_store as store  # noqa: E402
import fake_absolute as fake  # noqa: E402

FAILS = []


def check(cond, label):
    print(("PASS  " if cond else "FAIL  ") + label)
    if not cond:
        FAILS.append(label)


now = time.time()
srv = fake.FakeAbsolute(home, fake.make_events(now - 3600, now, 6), fake.make_devices(5, now))
_ctx = api.ssl_context


def ctx(self):
    c = _ctx()
    c.load_verify_locations(srv.ca)
    return c


api.Client.base_url = lambda self: srv.url
api.Client.make_ssl_context = ctx
H = rest.Handler()


def call(method, path, form=None):
    req = {"method": method, "rest_path": "/absolute_se/" + path, "session": {"user": "admin", "authtoken": "user-key"},
           "form": list((form or {}).items()) if method == "POST" else [], "query": []}
    out = H.handle(json.dumps(req))
    return out["status"], out["payload"]


def state():
    return json.load(open(os.environ["FAKE_SPLUNKD_STATE"]))


s, p = call("GET", "inputs")
check(s == 200 and p["inputs"] == [] and p["accounts"] == [] and "main" in p["indexes"], "empty inputs page")
s, p = call("POST", "accounts", {"action": "save", "name": "abs", "api_host": "evil.example.com",
                                 "token_id": fake.TOKEN_ID, "token_secret": fake.SECRET})
check(s == 400 and "API host" in p["error"], "non-Absolute API host refused")
s, p = call("POST", "accounts", {"action": "save", "name": "abs", "api_host": "api.absolute.com",
                                 "token_id": fake.TOKEN_ID, "token_secret": "has space"})
check(s == 400 and "Secret key" in p["error"], "bad secret refused")
s, p = call("POST", "accounts", {"action": "save", "name": "abs", "api_host": "api.absolute.com",
                                 "token_id": fake.TOKEN_ID, "token_secret": fake.SECRET,
                                 "proxy_url": "http://user:pw@proxy:8080"})
check(s == 400 and "Proxy" in p["error"], "proxy with credentials refused")
s, p = call("POST", "accounts", {"action": "save", "name": "abs", "api_host": "api.absolute.com",
                                 "token_id": fake.TOKEN_ID, "token_secret": fake.SECRET})
check(s == 200 and p["ok"], "account saved")
s, p = call("GET", "accounts")
acct = p["accounts"][0]
check(acct["name"] == "abs" and acct["token_id_hint"] == "..." + fake.TOKEN_ID[-6:] and
      fake.SECRET not in json.dumps(p) and fake.TOKEN_ID not in json.dumps(p), "account listed without secrets")
check(all(v["realm"] == store.REALM for v in state()["passwords"].values()), "stored in storage/passwords")
s, p = call("POST", "accounts", {"action": "test", "name": "abs"})
check(s == 200 and p["ok"] and p["checks"] == {"siem_events": "OK", "devices": "OK"}, f"test: {p}")
s, p = call("POST", "accounts", {"action": "save", "name": "abs", "api_host": "api.absolute.com", "token_id": "",
                                 "token_secret": "", "proxy_url": ""})
s2, p2 = call("POST", "accounts", {"action": "test", "name": "abs"})
check(s == 200 and p2["ok"], "edit with empty token fields keeps the saved token")
call("POST", "accounts", {"action": "save", "name": "wrong", "api_host": "api.absolute.com",
                          "token_id": fake.TOKEN_ID, "token_secret": "wrong-secret"})
s, p = call("POST", "accounts", {"action": "test", "name": "wrong"})
check(s == 200 and not p["ok"] and "not accepted" in p["checks"]["siem_events"], "test reports a refused token")

E = {"action": "create", "kind": "events", "name": "ev", "account": "abs", "index": "endpoint"}
s, p = call("POST", "inputs", dict(E, page_size="5000"))
check(s == 400 and "page_size" in p["error"], f"validation (by the input script) refuses page_size: {p.get('error')}")
s, p = call("POST", "inputs", dict(E, account="nope"))
check(s == 400 and "is not saved" in p["error"], "unknown account refused")
s, p = call("POST", "inputs", dict(E, interval="5"))
check(s == 400 and "interval" in p["error"], "too short an interval refused")
s, p = call("POST", "inputs", E)
check(s == 200 and p["inputs"][0]["name"] == "ev" and p["inputs"][0]["interval"] == "300", "events input created (interval 300)")
s, p = call("POST", "inputs", dict(E, kind="devices"))
check(s == 400 and "already exists" in p["error"], "names unique across kinds")
s, p = call("POST", "inputs", dict(E, kind="devices", name="dev", exclude_fields="printers,usbs", interval="15 2 * * *"))
check(s == 200 and any(i["name"] == "dev" and i["kind"] == "devices" and i["interval"] == "15 2 * * *"
                       for i in p["inputs"]), "devices input created with a cron schedule")
s, p = call("POST", "inputs", dict(E, kind="devices", name="dev2", exclude_fields="deviceUid"))
check(s == 400 and "cannot be left out" in p["error"], "deviceUid cannot be excluded")
conf = open(os.path.join(home, "etc", "apps", "TA-absolute-secure-endpoint", "local", "inputs.conf")).read()
check("[absolute_events://ev]" in conf and "[absolute_devices://dev]" in conf, "saved in local/inputs.conf")

s, p = call("POST", "inputs", {"action": "edit", "kind": "events", "name": "ev", "delay_minutes": "7"})
check(s == 200 and state()["inputs"]["absolute_events"]["ev"]["delay_minutes"] == "7",
      "edit with only the changed setting (validated with the saved ones)")
check(["absolute_events", "ev", "disable"] in state()["restarts"], "edit restarts the input")
s, p = call("POST", "inputs", {"action": "run", "kind": "devices", "name": "dev"})
marker = store.run_now_path("absolute_devices", "dev")
check(s == 200 and os.path.exists(marker), "Run now leaves the run-now marker for the devices input")
import fcntl  # noqa: E402
lock_file = store.lock_path("absolute_devices", "dev")
os.makedirs(os.path.dirname(lock_file), exist_ok=True)
held = open(lock_file, "w")
fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)             # a run of the input in progress
restarts = len(state()["restarts"])
s, p = call("POST", "inputs", {"action": "run", "kind": "devices", "name": "dev"})
check(s == 409 and "in progress" in p["error"] and len(state()["restarts"]) == restarts,
      "Run now refused while a run is in progress (the input is not restarted)")
fcntl.flock(held, fcntl.LOCK_UN)
held.close()
s, p = call("POST", "inputs", {"action": "run", "kind": "devices", "name": "dev"})
check(s == 200, "Run now accepted once the run has finished")
s, p = call("POST", "inputs", {"action": "disable", "kind": "devices", "name": "dev"})
check(s == 200 and [i for i in p["inputs"] if i["name"] == "dev"][0]["disabled"], "disable")
s, p = call("POST", "inputs", {"action": "run", "kind": "devices", "name": "dev"})
check(s == 400 and "disabled" in p["error"], "Run now on a disabled input refused")
s, p = call("POST", "accounts", {"action": "delete", "name": "abs"})
check(s == 400 and "used by" in p["error"], "an account in use cannot be deleted")
s, p = call("GET", "accounts")
check(sorted(p["accounts"][0]["used_by"]) == ["dev (devices)", "ev (events)"], "accounts show the inputs using them")

ck = store.state_path("absolute_events", "ev")
os.makedirs(os.path.dirname(ck), exist_ok=True)
open(ck, "w").write("{}")
s, p = call("POST", "inputs", {"action": "delete", "kind": "events", "name": "ev"})
check(s == 200 and not os.path.exists(ck) and all(i["name"] != "ev" for i in p["inputs"]),
      "delete removes the input and its checkpoint")
call("POST", "inputs", {"action": "delete", "kind": "devices", "name": "dev"})
check(not os.path.exists(marker), "delete removes the run-now marker")
s, p = call("POST", "accounts", {"action": "delete", "name": "abs"})
check(s == 200 and "abs:" not in json.dumps(state()["passwords"]).replace("absolute", ""), "account deleted")
s, p = call("POST", "inputs", {"action": "bogus", "kind": "events", "name": "x"})
check(s == 400, "unknown action refused")
s, p = call("GET", "nothing")
check(s == 404, "unknown path")
log = open(os.path.join(home, "var", "log", "splunk", "absolute_se-webapi.log")).read()
check("action=save" in log and "action=create" in log and fake.SECRET not in log and fake.TOKEN_ID not in log,
      "Inputs page actions logged, without secrets")
srv.close()
print("\nALL PASSED" if not FAILS else f"\n{len(FAILS)} failed")
sys.exit(1 if FAILS else 0)
