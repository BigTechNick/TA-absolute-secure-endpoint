#!/usr/bin/env python3
"""
ui_test.py <out dir> - drives the Inputs page in headless Chromium against the real REST
handler (fake 'splunk' package, fake_absolute for the account test), outside Splunk.
splunkjs is replaced by a small stand-in: service.get/post go to this test server, which
calls absolute_se_rest.Handler as splunkd would. Saves screenshots to <out dir>.
"""
import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(os.path.dirname(HERE), "TA-absolute-secure-endpoint")
BIN = os.path.join(APP, "bin")
OUT = sys.argv[1]
JQUERY = "/usr/share/javascript/jquery/jquery.js"
os.makedirs(OUT, exist_ok=True)
home = tempfile.mkdtemp(prefix="abs_ui_")
os.makedirs(os.path.join(home, "var", "log", "splunk"))
shutil.copytree(APP, os.path.join(home, "etc", "apps", "TA-absolute-secure-endpoint"))
os.environ.update(SPLUNK_HOME=home, FAKE_SPLUNKD_STATE=os.path.join(home, "splunkd.json"), FAKE_APP_BIN=BIN,
                  PYTHONPATH=os.path.join(HERE, "fake_splunk"))
sys.path[:0] = [os.path.join(HERE, "fake_splunk"), BIN, HERE]
import absolute_se_api as api  # noqa: E402
import absolute_se_rest as rest  # noqa: E402
import fake_absolute as fake  # noqa: E402

now = time.time()
srv = fake.FakeAbsolute(home, fake.make_events(now - 3600, now, 6), fake.make_devices(5, now))
_ctx = api.ssl_context


def ctx(self):
    c = _ctx()
    c.load_verify_locations(srv.ca)
    return c


api.Client.base_url = lambda self: srv.url
api.Client.make_ssl_context = ctx
HANDLER = rest.Handler()
PAGE = """<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="/static/absolute_inputs.css">
<style>body{font-family:Helvetica,Arial,sans-serif;margin:20px;color:#1d1f24}
.btn{padding:4px 10px;border:1px solid #aaa;border-radius:3px;background:#f5f5f5;cursor:pointer}
.btn-primary{background:#1a73c9;color:#fff;border-color:#1a73c9}.btn-small{font-size:12px;padding:2px 8px}
table.table{border-collapse:collapse}table.table th,table.table td{border-bottom:1px solid #ddd;padding:6px 8px;text-align:left}
</style>
<script src="/jquery.js"></script>
<script>
var MODULES = {};
window.require = function (deps, fn) {
  setTimeout(function () { fn.apply(null, deps.map(function (d) { return MODULES[d]; })); }, 0);
};
function call(method, url, params, cb) {
  var body = new URLSearchParams(params).toString();
  fetch('/api' + url + (method === 'GET' ? '?' + body : ''), {method: method,
    headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: method === 'GET' ? undefined : body})
    .then(function (r) { return r.json().then(function (d) { return {status: r.status, data: d}; }); })
    .then(function (res) { if (res.status >= 400) { cb({status: res.status, data: res.data}); }
                           else { cb(null, {status: res.status, data: res.data}); } });
}
MODULES['jquery'] = jQuery;
MODULES['splunkjs/mvc'] = {createService: function () {
  return {get: function (u, p, cb) { call('GET', u, p, cb); }, post: function (u, p, cb) { call('POST', u, p, cb); }}; }};
window.SEARCHES = [];
MODULES['splunkjs/mvc/searchmanager'] = function (opts) {
  var handlers = [];
  window.SEARCHES.push(opts.search);
  this.data = function () { return {on: function (ev, h) { handlers.push(h); }}; };
  this.startSearch = function () {
    setTimeout(function () { handlers.forEach(function (h) { h({data: function () { return {
      fields: ['input_kind', 'input', 'last_run', 'result', 'detail', 'behind'],
      rows: [['events', 'abs-events', String(Date.now() / 1000 - 90), 'done',
              'written 500, duplicates 50, excluded 0, api calls 2, window a to b, behind 5.0 min, 1.8 s', '5.0']]};
      }}); }); }, 50);
  };
};
MODULES['splunkjs/mvc/simplexml/ready!'] = {};
window.onerror = function (m) { document.title = 'JSERROR ' + m; };
</script>
<script src="/static/absolute_inputs.js"></script></head>
<body><div id="absolute-inputs-app">Loading...</div></body></html>"""


class Server(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def api(self, method):
        url = urllib.parse.urlparse(self.path)
        form = urllib.parse.parse_qsl(url.query, keep_blank_values=True)
        if method == "POST":
            n = int(self.headers.get("Content-Length") or 0)
            form = urllib.parse.parse_qsl(self.rfile.read(n).decode(), keep_blank_values=True)
        req = {"method": method, "rest_path": url.path[len("/api/services"):],
               "session": {"user": "admin", "authtoken": "user-key"}, "form": form if method == "POST" else [],
               "query": form if method == "GET" else []}
        out = HANDLER.handle(json.dumps(req))
        self.send(out["status"], json.dumps(out["payload"]), "application/json")

    def do_GET(self):
        if self.path.startswith("/api/"):
            return self.api("GET")
        if self.path == "/":
            return self.send(200, PAGE, "text/html")
        if self.path == "/jquery.js":
            return self.send(200, open(JQUERY, "rb").read(), "application/javascript")
        if self.path.startswith("/static/"):
            f = os.path.join(APP, "appserver", "static", os.path.basename(self.path))
            ctype = "text/css" if f.endswith(".css") else "application/javascript"
            return self.send(200, open(f, "rb").read(), ctype)
        self.send(404, "nope", "text/plain")

    def do_POST(self):
        self.api("POST")


def main():
    from playwright.sync_api import sync_playwright
    web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Server)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{web.server_port}/"
    fails = []

    def check(cond, label):
        print(("PASS  " if cond else "FAIL  ") + label)
        if not cond:
            fails.append(label)

    def state():
        return json.load(open(os.environ["FAKE_SPLUNKD_STATE"]))

    def submit(page):
        page.click(".abs-modal-buttons .btn-primary")

    def closed(page):
        page.wait_for_selector(".abs-modal", state="detached", timeout=60000)
        page.wait_for_timeout(500)

    with sync_playwright() as p:
        b = p.chromium.launch()
        page = b.new_page(viewport={"width": 1280, "height": 860})
        page.on("dialog", lambda d: d.accept())
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(url)
        page.wait_for_selector("#abs-input-rows")
        page.wait_for_timeout(500)
        check("No inputs yet" in page.inner_text("#abs-input-rows"), "empty inputs table shows what to do")
        check("No Absolute accounts" in page.inner_text("#abs-account-rows"), "empty accounts table shows what to do")
        page.screenshot(path=os.path.join(OUT, "ui-1-empty.png"), full_page=True)

        page.click("text=Add input")
        page.wait_for_timeout(300)
        check("Save an Absolute account first" in page.inner_text(".abs-flash"), "add input without an account explains")

        page.click("text=Add account")
        page.fill(".abs-modal input[name=name]", "absolute")
        page.fill(".abs-modal input[name=api_host]", "api.example.com")
        page.fill(".abs-modal input[name=token_id]", fake.TOKEN_ID)
        page.fill(".abs-modal input[name=token_secret]", fake.SECRET)
        submit(page)
        page.wait_for_selector(".abs-form-error:visible")
        check("API host" in page.inner_text(".abs-form-error"), "wrong API host shown in the form")
        page.fill(".abs-modal input[name=api_host]", "api.absolute.com")
        page.screenshot(path=os.path.join(OUT, "ui-2-account.png"), full_page=True)
        submit(page)
        closed(page)
        page.wait_for_function("document.querySelector('.abs-flash').innerText.indexOf('SIEM events: OK') >= 0",
                               timeout=30000)
        check("Devices: OK" in page.inner_text(".abs-flash"), "account saved and tested")
        rows = page.inner_text("#abs-account-rows")
        check("absolute" in rows and "api.absolute.com" in rows and fake.SECRET not in page.content() and
              fake.TOKEN_ID not in page.content(), "account listed, token not shown")

        page.click("text=Add input")
        page.fill(".abs-modal input[name=name]", "abs-events")
        page.fill(".abs-modal input[name=index]", "endpoint")
        page.click(".abs-modal >> text=Advanced settings")
        page.fill(".abs-modal input[name=page_size]", "5000")
        submit(page)
        page.wait_for_selector(".abs-form-error:visible")
        check("page_size" in page.inner_text(".abs-form-error"), "validation error shown in the form")
        page.fill(".abs-modal input[name=page_size]", "500")
        page.fill(".abs-modal input[name=exclude_event_types]", "ApplicationUpdated")
        page.screenshot(path=os.path.join(OUT, "ui-3-add-events.png"), full_page=True)
        submit(page)
        closed(page)
        saved = state()["inputs"]["absolute_events"]["abs-events"]
        check(saved.get("page_size") == "500" and saved.get("interval") == "300" and saved.get("index") == "endpoint"
              and saved.get("exclude_event_types") == "ApplicationUpdated" and "connected_within_hours" not in saved,
              f"events input saved with its own settings only {saved}")

        page.click("text=Add input")
        page.select_option(".abs-modal select[name=kind]", "devices")
        check(page.input_value(".abs-modal input[name=interval]") == "86400", "devices default interval 86400")
        page.fill(".abs-modal input[name=name]", "abs-devices")
        page.fill(".abs-modal input[name=index]", "endpoint")
        page.click(".abs-modal >> text=Leave out peripherals")
        page.screenshot(path=os.path.join(OUT, "ui-4-add-devices.png"), full_page=True)
        submit(page)
        closed(page)
        saved = state()["inputs"]["absolute_devices"]["abs-devices"]
        check(saved.get("exclude_fields", "").startswith("printers,usbs") and saved.get("interval") == "86400" and
              "delay_minutes" not in saved, f"devices input saved {saved}")
        page.wait_for_timeout(800)
        rows = page.inner_text("#abs-input-rows")
        check("abs-events" in rows and "every 5 min to endpoint" in rows and "abs-devices" in rows and
              "every 24 h to endpoint" in rows, "both inputs listed with schedule and index")
        check("OK" in rows and "written 500" in rows, "status from the log search shown")
        check("Enabled - no run logged yet" in rows, "input without runs says so")
        page.screenshot(path=os.path.join(OUT, "ui-5-inputs.png"), full_page=True)

        page.click("#abs-input-rows tr:has-text('abs-events') >> button:text-is('Edit')")
        page.click(".abs-modal >> text=Advanced settings")
        page.fill(".abs-modal input[name=delay_minutes]", "7")
        submit(page)
        closed(page)
        check(state()["inputs"]["absolute_events"]["abs-events"].get("delay_minutes") == "7", "edit saved")

        page.click("#abs-input-rows tr:has-text('abs-devices') >> button:text-is('Run now')")
        page.wait_for_timeout(500)
        check("started" in page.inner_text(".abs-flash"), "Run now")
        page.click("#abs-input-rows tr:has-text('abs-devices') >> button:text-is('Disable')")
        page.wait_for_timeout(500)
        check("Disabled" in page.inner_text("#abs-input-rows tr:has-text('abs-devices')"), "disable")
        page.click("#abs-input-rows tr:has-text('abs-devices') >> button:text-is('Enable')")
        page.wait_for_timeout(500)

        page.click("#abs-account-rows button:text-is('Delete')")
        page.wait_for_timeout(500)
        check("used by" in page.inner_text(".abs-flash"), "deleting an account in use is refused")
        page.click("#abs-account-rows button:text-is('Test')")
        page.wait_for_function("document.querySelector('.abs-flash').innerText.indexOf('Devices: OK') >= 0",
                               timeout=30000)
        check(True, "Test button")

        page.click("#abs-input-rows tr:has-text('abs-events') >> button:text-is('Delete')")
        page.wait_for_timeout(500)
        page.click("#abs-input-rows tr:has-text('abs-devices') >> button:text-is('Delete')")
        page.wait_for_timeout(500)
        check("No inputs yet" in page.inner_text("#abs-input-rows"), "inputs deleted")
        page.click("#abs-account-rows button:text-is('Delete')")
        page.wait_for_timeout(600)
        check("No Absolute accounts" in page.inner_text("#abs-account-rows"), "account deleted")
        page.set_viewport_size({"width": 420, "height": 800})
        page.screenshot(path=os.path.join(OUT, "ui-6-narrow.png"), full_page=True)
        check(not errors and not page.title().startswith("JSERROR"), f"no JavaScript errors {errors}")
        b.close()
    srv.close()
    print("\nALL PASSED" if not fails else f"\n{len(fails)} failed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
