# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
absolute_se_rest.py - REST API behind the add-on's Inputs page.

  /services/absolute_se/inputs
      GET                                  inputs of both kinds, account names, indexes
      POST action=create|edit              kind (events|devices), name, input settings
      POST action=enable|disable|run|delete   kind, name
  /services/absolute_se/accounts
      GET                                  saved accounts (never the secret key)
      POST action=save                     name, api_host, token_id, token_secret, proxy_url
                                           (empty token_id / token_secret keep the saved ones)
      POST action=test                     name: one small call per data type to the Absolute API
      POST action=delete                   name

Every change is made with the signed-in user's own session, so Splunk's
normal permissions apply (admin rights to change inputs and the credential
store). Accounts are stored encrypted in Splunk's credential store.
"""
import json
import logging
import logging.handlers
import os
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import absolute_se_api as api  # noqa: E402
import absolute_se_store as store  # noqa: E402
from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

COMMON = ("account", "log_level", "index", "interval")
FIELDS = {kind: COMMON + tuple(store.NUMBERS[kind]) + tuple(k for k in store.TEXTS[kind] if k not in COMMON)
          for kind in store.SCHEMES}
DEFAULT_INTERVAL = {"events": "300", "devices": "86400"}


def get_logger():
    log = logging.getLogger("absolute_se_rest")
    if not log.handlers:
        path = os.path.join(store.splunk_home(), "var", "log", "splunk", "absolute_se-webapi.log")
        try:
            handler = logging.handlers.RotatingFileHandler(path, maxBytes=5 << 20, backupCount=2)
        except OSError:
            handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
    return log


def form_of(req):
    form = {}
    for key in ("query", "form"):
        for pair in req.get(key) or []:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                form[pair[0]] = pair[1]
    payload = req.get("payload")
    if not req.get("form") and isinstance(payload, str) and payload:
        try:
            form.update(json.loads(payload))
        except ValueError:
            form.update({k: v[-1] for k, v in urllib.parse.parse_qs(payload, keep_blank_values=True).items()})
    return form


def reply(payload, status=200):
    return {"payload": payload, "status": status}


def inputs_path(kind):
    return f"data/inputs/{store.SCHEMES[kind]}"


class Api:
    def __init__(self, splunkd, user, log):
        self.splunkd, self.user, self.log = splunkd, user, log
        self.accounts = store.Accounts(splunkd)

    # ---- inputs
    def inputs(self):
        out = []
        for kind, scheme in store.SCHEMES.items():
            body = self.splunkd.ok("GET", inputs_path(kind), {"count": 0}, allow=(200,))
            for entry in store.entries(body):
                content = entry.get("content", {})
                item = {k: content.get(k, "") for k in FIELDS[kind]}
                item.update(kind=kind, name=entry.get("name"),
                            disabled=content.get("disabled") in (True, "1", 1, "true"),
                            status=store.read_status(kind, entry.get("name")))
                out.append(item)
        out.sort(key=lambda i: (i["name"].lower(), i["kind"]))
        return out

    def get_inputs(self):
        indexes = []
        status, body = self.splunkd.call("GET", "/services/data/indexes", {"count": 0, "datatype": "event"})
        if status == 200:
            indexes = sorted(e.get("name") for e in store.entries(body)
                             if not e.get("content", {}).get("disabled"))
        names = []
        try:
            names = [a["name"] for a in self.accounts.list()]
        except store.StoreError as exc:
            self.log.warning("listing accounts failed: %s", exc)
        return {"inputs": self.inputs(), "accounts": names, "indexes": indexes}

    def find(self, kind, name):
        for item in self.inputs():
            if item["name"] == name and item["kind"] == kind:
                return item
        raise store.StoreError(f"{kind} input '{name}' not found", 404)

    def post_inputs(self, form):
        action = form.get("action", "")
        kind = form.get("kind", "")
        name = (form.get("name") or "").strip()
        if kind not in store.SCHEMES:
            raise store.StoreError("kind must be events or devices")
        if not store.NAME_RE.match(name):
            raise store.StoreError("Input name: letters, digits, '.', '_' or '-' (max 64), "
                                   "starting with a letter or digit")
        scheme = store.SCHEMES[kind]
        path = f"{inputs_path(kind)}/{store.quote(name)}"
        if action in ("create", "edit"):
            args = {k: str(form[k]).strip() for k in FIELDS[kind] if k in form}
            if action == "create":
                if any(i["name"] == name for i in self.inputs()):
                    raise store.StoreError(f"an input named '{name}' already exists")
                args["interval"] = args.get("interval") or DEFAULT_INTERVAL[kind]
                self.check_interval(args["interval"])
                self.splunkd.ok("POST", inputs_path(kind), dict(args, name=name))
            else:
                current = self.find(kind, name)
                if "interval" in args:
                    args["interval"] = args["interval"] or DEFAULT_INTERVAL[kind]
                    self.check_interval(args["interval"])
                self.splunkd.ok("POST", path, args)
                if not current["disabled"]:             # restart with the new settings
                    self.restart(path)
        elif action in ("enable", "disable"):
            self.splunkd.ok("POST", f"{path}/{action}")
        elif action == "run":
            current = self.find(kind, name)
            if current["disabled"]:
                raise store.StoreError(f"input '{name}' is disabled; enable it first")
            if store.run_in_progress(scheme, name):         # Run now restarts the input: it would stop that run
                raise store.StoreError(f"a run of input '{name}' is in progress; Run now would stop it. "
                                       "Try again when it has finished.", 409)
            self.splunkd.ok("POST", f"{path}/disable")      # with the user's own rights
            if kind == "devices":                      # otherwise a run soon after the last one is skipped
                marker = store.run_now_path(scheme, name)
                os.makedirs(os.path.dirname(marker), exist_ok=True)
                with open(marker, "w") as fh:
                    fh.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            self.splunkd.ok("POST", f"{path}/enable")
        elif action == "delete":
            self.find(kind, name)
            self.splunkd.ok("DELETE", path)
            for leftover in (store.state_path(scheme, name), store.run_now_path(scheme, name),
                             store.lock_path(scheme, name)):
                try:
                    os.remove(leftover)
                except OSError:
                    pass
        else:
            raise store.StoreError("action must be create, edit, enable, disable, run or delete")
        self.log.info("user=%s kind=%s input=%s action=%s", self.user, kind, name, action)
        return {"ok": True, "inputs": self.inputs()}

    @staticmethod
    def check_interval(value):
        value = str(value).strip()
        if value.isdigit():
            if not 60 <= int(value) <= 31536000:
                raise store.StoreError("interval: seconds from 60 to 31536000, or a cron schedule")
        elif len(value.split()) != 5:
            raise store.StoreError("interval: seconds (e.g. 300) or a cron schedule (e.g. 15 2 * * *)")

    def restart(self, path):
        self.splunkd.ok("POST", f"{path}/disable")
        self.splunkd.ok("POST", f"{path}/enable")

    # ---- accounts
    def get_accounts(self):
        accounts = self.accounts.list()
        try:
            used = {}
            for item in self.inputs():
                used.setdefault(item["account"], []).append(f"{item['name']} ({item['kind']})")
            for account in accounts:
                account["used_by"] = used.get(account["name"], [])
        except store.StoreError:
            pass
        return {"accounts": accounts}

    def post_accounts(self, form):
        action = form.get("action", "")
        name = (form.get("name") or "").strip()
        if action == "save":
            doc = {k: form.get(k) for k in ("api_host", "token_id", "token_secret", "proxy_url")}
            saved = self.accounts.save(name, doc, self.user)
            self.log.info("user=%s account=%s action=save api_host=%s proxy=%s", self.user, name,
                          saved["api_host"], "yes" if saved["proxy_url"] else "no")
            return {"ok": True, "account": saved}
        if action == "test":
            result = self.test(self.accounts.get(name))
            self.log.info("user=%s account=%s action=test result=%s", self.user, name,
                          "ok" if result["ok"] else "failed")
            return result
        if action == "delete":
            users = [f"{i['name']} ({i['kind']})" for i in self.inputs() if i["account"] == name]
            if users:
                raise store.StoreError(f"'{name}' is used by input(s) {', '.join(users)}; "
                                       "change or delete them first")
            self.accounts.delete(name)
            self.log.info("user=%s account=%s action=delete", self.user, name)
            return {"ok": True}
        raise store.StoreError("action must be save, test or delete")

    @staticmethod
    def test(account):
        """One small call per data type: is the token accepted, and may it read SIEM events and devices?"""
        now = int(time.time())
        checks = {}
        try:   # two calls of at most 12 s: an answer within Splunk Web's 30 s
            client = store.client_for(account, timeout=12, max_attempts=1)
        except api.ApiError as exc:
            return {"ok": False, "checks": {"account": str(exc)}, "api_host": account.get("api_host", "")}
        calls = (("siem_events", lambda: next(iter(api.siem_event_pages(client, now - 900, now - 300, 1)))),
                 ("devices", lambda: next(iter(api.device_pages(client, None, 1)))))
        for label, call in calls:
            if any(str(v).startswith("cannot reach") or "could not be verified" in str(v) for v in checks.values()):
                checks[label] = "not tried (see above)"
                continue
            try:
                call()
                checks[label] = "OK"
            except api.ApiError as exc:
                checks[label] = str(exc)
            except Exception as exc:
                checks[label] = f"{type(exc).__name__}: {exc}"
        return {"ok": all(v == "OK" for v in checks.values()), "checks": checks,
                "api_host": account["api_host"]}


class Handler(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        PersistentServerConnectionApplication.__init__(self)
        self.log = get_logger()

    def handle(self, in_string):
        try:
            req = json.loads(in_string)
            session = req.get("session") or {}
            handler = Api(store.Splunkd(session.get("authtoken")), session.get("user", ""), self.log)
            method = (req.get("method") or "GET").upper()
            path = (req.get("rest_path") or "").rstrip("/")
            form = form_of(req)
            if method == "DELETE":
                method, form["action"] = "POST", "delete"
            if path.endswith("/inputs"):
                return reply(handler.get_inputs() if method == "GET" else handler.post_inputs(form))
            if path.endswith("/accounts"):
                return reply(handler.get_accounts() if method == "GET" else handler.post_accounts(form))
            return reply({"error": f"unknown path {path}"}, 404)
        except store.StoreError as exc:
            return reply({"error": str(exc)}, exc.status if 400 <= exc.status < 600 else 400)
        except Exception as exc:                                    # keep the handler alive
            self.log.exception("request failed")
            return reply({"error": f"{type(exc).__name__}: {exc}"}, 500)
