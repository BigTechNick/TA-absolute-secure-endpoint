"""
Fake splunkd REST for tests: storage/passwords, data/inputs/absolute_events and
absolute_devices (with external validation through the real scripts), data/indexes.
State lives in the JSON file named by FAKE_SPLUNKD_STATE. Like splunkd, inputs created
under servicesNS/nobody/<app> are also written to the app's local/inputs.conf.
"""
import json
import os
import re
import subprocess
import sys
import urllib.parse
from xml.sax.saxutils import escape

from splunk import RESTException

APP = "TA-absolute-secure-endpoint"
SCHEMES = ("absolute_events", "absolute_devices")


class Response:
    def __init__(self, status):
        self.status = status


def _load():
    path = os.environ["FAKE_SPLUNKD_STATE"]
    if os.path.exists(path):
        with open(path) as fh:
            return json.load(fh)
    return {"passwords": {}, "inputs": {s: {} for s in SCHEMES}, "indexes": ["main", "endpoint"]}


def _save(state):
    with open(os.environ["FAKE_SPLUNKD_STATE"], "w") as fh:
        json.dump(state, fh, indent=1)
    local = os.path.join(os.environ["SPLUNK_HOME"], "etc", "apps", APP, "local")
    os.makedirs(local, exist_ok=True)
    with open(os.path.join(local, "inputs.conf"), "w") as fh:
        for scheme in SCHEMES:
            for name, params in sorted(state["inputs"].get(scheme, {}).items()):
                fh.write(f"[{scheme}://{name}]\n")
                for key, value in params.items():
                    fh.write(f"{key} = {int(value) if isinstance(value, bool) else value}\n")
                fh.write("\n")


def _json(status, entries=None, messages=None):
    body = {"entry": entries or []}
    if messages:
        body["messages"] = [{"type": "ERROR", "text": m} for m in messages]
    return Response(status), json.dumps(body)


def _script(scheme):
    return os.path.join(os.environ["FAKE_APP_BIN"], scheme + ".py")


def _validate(scheme, name, params):
    items = "".join(f'<param name="{escape(k)}">{escape(str(v))}</param>' for k, v in params.items())
    xml = (f"<items><server_host>test</server_host><server_uri>https://127.0.0.1:8089</server_uri>"
           f"<session_key>system-key</session_key><checkpoint_dir>/tmp</checkpoint_dir>"
           f'<item name="{escape(name)}">{items}</item></items>')
    res = subprocess.run([sys.executable, _script(scheme), "--validate-arguments"], input=xml,
                         capture_output=True, text=True, env=dict(os.environ, FAKE_IN_VALIDATION=scheme))
    if res.returncode:
        m = re.search(r"<message>(.*)</message>", res.stdout, re.S)
        return m.group(1) if m else (res.stderr or "validation failed")
    return None


COMMON_INPUT_ARGS = {"name", "index", "host", "source", "sourcetype", "interval"}
_scheme_args = {}


def scheme_args(scheme):
    if scheme not in _scheme_args:
        import xml.etree.ElementTree as ET
        out = subprocess.run([sys.executable, _script(scheme), "--scheme"], capture_output=True, text=True,
                             check=True).stdout
        _scheme_args[scheme] = {a.get("name") for a in ET.fromstring(out).iter("arg")}
    return _scheme_args[scheme]


def unsupported(args, allowed):
    bad = sorted(k for k in args if k not in allowed and k != "output_mode")
    if bad:
        return _json(400, messages=[f'Argument "{bad[0]}" is not supported by this handler.'])
    return None


def simpleRequest(path, sessionKey=None, method="GET", getargs=None, postargs=None, raiseAllErrors=False, **_):
    if not sessionKey:
        raise RESTException(401, "no session")
    if os.environ.get("FAKE_IN_VALIDATION") and "data/inputs/" in path:
        raise RESTException(500, "fake: splunkd is busy with the request being validated")
    state = _load()
    p = urllib.parse.urlparse(path).path
    p = re.sub(r"^/servicesNS/[^/]+/[^/]+/", "", p)
    p = re.sub(r"^/services/", "", p)
    parts = [urllib.parse.unquote(x) for x in p.split("/")]
    args = dict(postargs or {})

    if parts[:2] == ["storage", "passwords"]:
        pw = state["passwords"]
        if len(parts) == 2 and method == "GET":
            return _json(200, [{"name": k, "content": v} for k, v in sorted(pw.items())])
        if len(parts) == 2 and method == "POST":
            key = f"{args['realm']}:{args['name']}:"
            if key in pw:
                return _json(409, messages=["An object with name=%s already exists" % args["name"]])
            pw[key] = {"realm": args["realm"], "username": args["name"], "clear_password": args["password"]}
            _save(state)
            return _json(201)
        if len(parts) == 3 and method == "POST":           # update an existing entry's password
            if parts[2] not in pw:
                raise RESTException(404, "not found")
            pw[parts[2]]["clear_password"] = args["password"]
            _save(state)
            return _json(200)
        if len(parts) == 3 and method == "DELETE":
            if parts[2] not in pw:
                raise RESTException(404, "not found")
            del pw[parts[2]]
            _save(state)
            return _json(200)

    if parts[:2] == ["data", "inputs"] and len(parts) >= 3 and parts[2] in SCHEMES:
        scheme = parts[2]
        inputs = state["inputs"].setdefault(scheme, {})
        if len(parts) == 3 and method == "GET":
            return _json(200, [{"name": k, "content": v} for k, v in sorted(inputs.items())])
        if len(parts) == 3 and method == "POST":
            refused = unsupported(args, scheme_args(scheme) | COMMON_INPUT_ARGS)
            if refused:
                return refused
            name = args.pop("name")
            if name in inputs:
                return _json(409, messages=[f"{name} exists"])
            error = _validate(scheme, name, args)
            if error:
                return _json(400, messages=[error])
            inputs[name] = dict(args, disabled=False, index=args.get("index", "default"))
            _save(state)
            return _json(201)
        name = parts[3]
        if name not in inputs:
            raise RESTException(404, f"input {name} not found")
        if len(parts) == 4 and method == "GET":
            return _json(200, [{"name": name, "content": dict(inputs[name])}])
        if len(parts) == 4 and method == "POST":
            refused = unsupported(args, scheme_args(scheme) | COMMON_INPUT_ARGS)
            if refused:
                return refused
            error = _validate(scheme, name, args)          # like splunkd: only the arguments being changed
            if error:
                return _json(400, messages=[error])
            inputs[name].update(args)
        elif len(parts) == 4 and method == "DELETE":
            del inputs[name]
        elif len(parts) == 5 and parts[4] in ("enable", "disable"):
            inputs[name]["disabled"] = parts[4] == "disable"
            state.setdefault("restarts", []).append([scheme, name, parts[4]])
        _save(state)
        return _json(200)

    if parts[:2] == ["data", "indexes"]:
        return _json(200, [{"name": n, "content": {"disabled": False}} for n in state["indexes"]])
    raise RESTException(404, f"fake splunkd: no endpoint {path}")
