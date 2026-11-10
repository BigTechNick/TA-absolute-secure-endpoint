#!/usr/bin/env python3
"""
make_screenshots.py <out dir> - screenshots for the Splunkbase listing, with made-up data only.

  * Inputs page, Add account and Add input: the add-on's real Inputs page (appserver/static) in
    headless Chromium against the real REST handler, as in ui_test.py (fake splunkd, fake Absolute API).
  * Status and Overview: mock-ups of the two dashboards (same panels, columns and chart types as the
    Simple XML views) filled with invented sample data, rendered from HTML with inline SVG charts.

Every name, address and number is invented: example.com users, LT-/WS- device names, documentation
IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
"""
import base64
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(sys.argv[1])
os.makedirs(OUT, exist_ok=True)
sys.argv = [sys.argv[0], os.path.join(OUT, "_ui")]           # ui_test reads its own out dir from argv
import ui_test  # noqa: E402  (sets up the fake splunkd, fake Absolute API and the REST handler)

APP = ui_test.APP
ICON = base64.b64encode(open(os.path.join(APP, "static", "appIcon_2x.png"), "rb").read()).decode()
LABEL = "Nikhil Chawla Add-on for Absolute Secure Endpoint"
W, H = 1440, 960
COLORS = ["#1e93c6", "#f2b827", "#d6563c", "#6a5c9e", "#31a35f", "#ed8440", "#3863a0", "#a2cc3e", "#999999"]
rnd = random.Random(7)

CSS = """
*{box-sizing:border-box}
body{margin:0;background:#eef0f2;font-family:Inter,Helvetica,Arial,sans-serif;color:#1d1f24;font-size:13px}
.appbar{height:44px;background:#1F4E79;color:#fff;display:flex;align-items:center;justify-content:space-between;
  padding:0 20px}
.appbar .nav a{color:#dfe8f1;text-decoration:none;margin-right:22px;font-weight:600;font-size:14px;
  padding:12px 0;border-bottom:3px solid transparent}
.appbar .nav a.on{color:#fff;border-bottom-color:#fff}
.appbar .app{display:flex;align-items:center;gap:10px;font-weight:600;font-size:14px}
.appbar .app img{width:26px;height:26px;border-radius:4px;background:#fff}
"""
CSS_DASH = """
.page{padding:16px 20px 24px}
h1{font-size:22px;font-weight:600;margin:4px 0 4px}
.desc{color:#5c6773;margin:0 0 12px;max-width:1150px;line-height:1.45}
.inputs{display:flex;gap:16px;margin-bottom:14px}
.field label{display:block;font-size:12px;color:#5c6773;margin-bottom:4px}
.field .box{background:#fff;border:1px solid #c3cbd4;border-radius:3px;padding:6px 10px;min-width:170px}
.row{display:flex;gap:12px;margin-bottom:12px}
.panel{background:#fff;border:1px solid #dce1e6;border-radius:3px;padding:10px 12px;flex:1;min-width:0}
.panel h3{font-size:14px;font-weight:600;margin:0 0 8px}
table{border-collapse:collapse;width:100%}
th{text-align:left;font-weight:600;border-bottom:2px solid #c3cbd4;padding:5px 8px;white-space:nowrap;font-size:12px}
td{padding:5px 8px;border-bottom:1px solid #eceff2;white-space:nowrap;font-size:12px}
tr:nth-child(even) td{background:#f7f8fa}
td.num{text-align:right;font-variant-numeric:tabular-nums}
td.st{color:#fff;font-weight:600;text-align:center}
.ok{background:#2E8540 !important}.info{background:#3C6FB4 !important}.warn{background:#B26B00 !important}
.lvl-WARNING{color:#B26B00;font-weight:600}.lvl-INFO{color:#3863a0;font-weight:600}
.svg text{font-family:Inter,Helvetica,Arial,sans-serif}
.note{position:fixed;right:14px;bottom:8px;font-size:11px;color:#8a949e}
"""


def appbar(active):
    items = "".join(f'<a class="{"on" if n == active else ""}">{n}</a>'
                    for n in ("Status", "Overview", "Inputs", "Search", "More ▾"))
    return (f'<div class="appbar"><div class="nav">{items}</div><div class="app">'
            f'<img src="data:image/png;base64,{ICON}">{LABEL}</div></div>')


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def table(cols, rows, num=(), status=None, level=None):
    head = "".join(f"<th>{esc(c)}</th>" for c in cols)
    body = []
    for r in rows:
        cells = []
        for i, v in enumerate(r):
            cls = "num" if i in num else ""
            if status is not None and i == status:
                cls = "st " + {"OK": "ok", "NO RUN YET": "info"}.get(v, "warn")
            if level is not None and i == level:
                cls = f"lvl-{v}"
            cells.append(f'<td class="{cls}">{esc(v)}</td>')
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f"<table><tr>{head}</tr>{''.join(body)}</table>"


def nice(v):
    """Smallest 1, 2, 2.5 or 5 x 10^n that is >= v."""
    return min(step * 10 ** mag for step in (1, 2, 2.5, 5) for mag in range(0, 8) if step * 10 ** mag >= v)


def axes(w, h, ymax, ytitle, labels, every, m):
    l, r, t, b = m
    ph = h - t - b
    out = []
    for i in range(5):
        y = t + ph - ph * i / 4
        val = ymax * i / 4
        txt = f"{val:,.0f}" if ymax >= 20 else f"{val:g}"
        out.append(f'<line x1="{l}" x2="{w - r}" y1="{y:.1f}" y2="{y:.1f}" stroke="#e3e7eb"/>'
                   f'<text x="{l - 6}" y="{y + 4:.1f}" font-size="11" fill="#5c6773" text-anchor="end">{txt}</text>')
    out.append(f'<text x="14" y="{t + ph / 2:.0f}" font-size="11" fill="#5c6773" text-anchor="middle" '
               f'transform="rotate(-90 14 {t + ph / 2:.0f})">{esc(ytitle)}</text>')
    n = len(labels)
    band = (w - l - r) / n
    for i, lab in enumerate(labels):
        if i % every == 0:
            x = l + band * (i + 0.5)
            out.append(f'<text x="{x:.1f}" y="{h - b + 16}" font-size="11" fill="#5c6773" '
                       f'text-anchor="middle">{esc(lab)}</text>')
    return out, band


def legend(names, w, h, rows=1):
    x, y, out = 60, h - 16 - 18 * (rows - 1), []
    for i, n in enumerate(names):
        width = 24 + 7 * len(n)
        if x + width > w and x > 60:
            x, y = 60, y + 18
        out.append(f'<rect x="{x}" y="{y}" width="10" height="10" fill="{COLORS[i % len(COLORS)]}"/>'
                   f'<text x="{x + 14}" y="{y + 9}" font-size="11" fill="#1d1f24">{esc(n)}</text>')
        x += width
    return out


def columns(labels, series, w, h, ytitle, every=2, legend_rows=1):
    m = (58, 12, 10, 44 + 18 * (legend_rows - 1))
    ymax = nice(max(sum(s[i] for s in series.values()) for i in range(len(labels))) * 1.08)
    out, band = axes(w, h, ymax, ytitle, labels, every, m)
    ph = h - m[2] - m[3]
    for i in range(len(labels)):
        base = 0
        for k, (name, vals) in enumerate(series.items()):
            v = vals[i]
            y0 = m[2] + ph - ph * (base + v) / ymax
            hh = ph * v / ymax
            out.append(f'<rect x="{m[0] + band * i + band * 0.15:.1f}" y="{y0:.1f}" width="{band * 0.7:.1f}" '
                       f'height="{hh:.1f}" fill="{COLORS[k % len(COLORS)]}"/>')
            base += v
    out += legend(list(series), w, h, legend_rows)
    return f'<svg class="svg" width="{w}" height="{h}">{"".join(out)}</svg>'


def lines(labels, series, w, h, ytitle, every=2):
    m = (58, 12, 10, 44)
    ymax = nice(max(max(v) for v in series.values()) * 1.15)
    out, band = axes(w, h, ymax, ytitle, labels, every, m)
    ph = h - m[2] - m[3]
    for k, (name, vals) in enumerate(series.items()):
        pts = " ".join(f"{m[0] + band * (i + 0.5):.1f},{m[2] + ph - ph * v / ymax:.1f}" for i, v in enumerate(vals))
        out.append(f'<polyline points="{pts}" fill="none" stroke="{COLORS[k]}" stroke-width="2"/>')
    out += legend(list(series), w, h)
    return f'<svg class="svg" width="{w}" height="{h}">{"".join(out)}</svg>'


def page(active, title, desc, fields, body):
    f = "".join(f'<div class="field"><label>{esc(a)}</label><div class="box">{esc(b)}</div></div>'
                for a, b in fields)
    return (f'<!doctype html><html><head><meta charset="utf-8"><style>{CSS}{CSS_DASH}</style></head><body>'
            f'{appbar(active)}<div class="page"><h1>{esc(title)}</h1><p class="desc">{esc(desc)}</p>'
            f'<div class="inputs">{f}</div>{body}</div><div class="note">Sample data</div></body></html>')


HOURS = [f"{h:02d}:00" for h in range(24)]
DAY = __import__("time").strftime("%Y-%m-%d")


def status_page():
    inputs = table(
        ["input", "input_kind", "status", "last_run", "last_written", "written_total", "behind_min", "last_devices",
         "last_mb", "last_log", "last_error"],
        [["absolute_devices", "devices", "OK", f"{DAY} 02:16:48", "", "", "", "1842", "31.8", f"{DAY} 02:16:48", ""],
         ["absolute_events", "events", "OK", f"{DAY} 23:55:04", "212", "71894", "5.0", "", "", f"{DAY} 23:55:04", ""]],
        num=(4, 5, 6, 7, 8), status=2)
    written = [int(1700 + 2600 * max(0, 1 - abs(h - 13) / 8) + rnd.uniform(-180, 180)) for h in range(24)]
    behind = [round(5.0 + (rnd.random() < 0.15) * rnd.uniform(0.2, 1.4), 1) for _ in range(24)]
    behind[9] = 11.0
    log = table(["_time", "input", "input_kind", "log_level", "message"], [
        [f"{DAY} 23:55:04", "absolute_events", "events", "INFO",
         "run done: written 212, duplicates 187, excluded 0, api calls 1, window 2026-10-21T04:40:00.000Z to "
         "2026-10-21T04:50:00.000Z, behind 5.0 min, 0.7 s"],
        [f"{DAY} 23:50:03", "absolute_events", "events", "INFO",
         "run done: written 198, duplicates 176, excluded 0, api calls 1, window 2026-10-21T04:35:00.000Z to "
         "2026-10-21T04:45:00.000Z, behind 5.0 min, 0.6 s"],
        [f"{DAY} 09:10:22", "absolute_events", "events", "WARNING",
         "HTTP 429: Too Many Requests - retry 1 of 5 in 30 s"],
        [f"{DAY} 02:16:48", "absolute_devices", "devices", "INFO",
         "run done: devices 1842, pages 19, api calls 19, 31.8 MB, 148.2 s"],
        [f"{DAY} 02:14:20", "absolute_devices", "devices", "INFO",
         "run started: account absolute (api.absolute.com), devices connected since 2026-10-19T07:14:20.000Z, "
         "page size 100"],
    ], level=3)
    body = (f'<div class="row"><div class="panel"><h3>Inputs now (last 25 hours)</h3>{inputs}</div></div>'
            f'<div class="row"><div class="panel"><h3>SIEM events written per run</h3>'
            f'{columns(HOURS, {"absolute_events": written}, 680, 250, "events")}</div>'
            f'<div class="panel"><h3>Minutes behind (end of the last collected window, SIEM events)</h3>'
            f'{lines(HOURS, {"absolute_events": behind}, 680, 250, "minutes")}</div></div>'
            f'<div class="row"><div class="panel"><h3>Run log: runs, first runs, skips, stops, failures</h3>'
            f'{log}</div></div>')
    return page("Status", "Status",
                "Collector health per input: last run, events and devices collected, how far behind, errors, and "
                "what reached the index. Collector logs come from index _internal; events from the index entered "
                "below (* = all indexes, slower).",
                [("Time range", "Last 24 hours"), ("Event index (* = all)", "endpoint"), ("Input", "All")], body)


TYPES = [("ApplicationUpdated", "Updated", 18402, 1611), ("NewApplicationDetected", "Installed", 6935, 1204),
         ("DeviceSystemInformationUpdated", "Updated", 5118, 1377), ("ApplicationUninstalled", "Uninstalled", 4276, 988),
         ("DeviceLocationUpdated", "Updated", 3862, 1296), ("AgentSelfHealingCall", "Self-Healed", 318, 241),
         ("UserLogin", "LoggedIn", 46, 0), ("DeviceVolumeAdded", "Added", 37, 31),
         ("DeviceBecameAVProtected", "Updated", 12, 12), ("AlertTriggered", "Triggered", 9, 7)]


def overview_page():
    types = table(["eventType", "verb", "count", "devices", "last_seen"],
                  [[t, v, f"{c:,}", d or "", f"{DAY} 23:{rnd.randint(40, 59):02d}:{rnd.randint(0, 59):02d}"]
                   for t, v, c, d in TYPES], num=(2, 3))
    top = ["ApplicationUpdated", "NewApplicationDetected", "DeviceSystemInformationUpdated", "ApplicationUninstalled",
           "DeviceLocationUpdated", "OTHER"]
    shares = [18402, 6935, 5118, 4276, 3862, 450]
    curve = [0.35 + 0.65 * max(0, 1 - abs(h - 13) / 8) for h in range(24)]
    tot = sum(curve)
    series = {n: [int(s * c / tot * rnd.uniform(0.9, 1.1)) for c in curve] for n, s in zip(top, shares)}
    console = table(["_time", "console_user", "eventType", "verb", "target", "detail", "src"], [
        [f"{DAY} 14:12:08", "alex.morgan@example.com", "UserLogin", "LoggedIn", "Absolute IDP", "", "203.0.113.24"],
        [f"{DAY} 14:05:51", "sam.lee@example.com", "LocationHistoryAccessed", "Accessed", "LT-0417", "",
         "203.0.113.31"],
        [f"{DAY} 13:48:30", "alex.morgan@example.com", "DeviceFrozen", "Frozen", "LT-1290", "DeviceFreeze-118",
         "203.0.113.24"],
        [f"{DAY} 13:21:14", "alex.morgan@example.com", "RuleUpdated", "Updated", "Device leaves the country", "",
         "203.0.113.24"],
        [f"{DAY} 12:57:02", "jordan.kim@example.com", "UserUpdated", "Updated", "sam.lee@example.com", "",
         "198.51.100.40"],
        [f"{DAY} 12:40:45", "jordan.kim@example.com", "UserLoginFailed", "Failed", "Absolute IDP", "",
         "198.51.100.40"],
    ])
    body = (f'<div class="row"><div class="panel" style="flex:0 0 610px"><h3>SIEM events by type</h3>{types}</div>'
            f'<div class="panel"><h3>SIEM events over time (top types)</h3>'
            f'{columns(HOURS, series, 760, 330, "count", legend_rows=2)}</div></div>'
            f'<div class="row"><div class="panel"><h3>Console activity (sign-ins, account and settings changes, '
            f'device actions, location lookups)</h3>{console}</div></div>')
    return page("Overview", "Overview",
                "What the Absolute data shows: SIEM event types, console activity, alerts, security posture "
                "changes, and the device inventory from the latest snapshot.",
                [("Time range", "Last 24 hours"), ("Index (* = all)", "endpoint")], body)


def overview_page2():
    alerts = table(["_time", "eventType", "signature", "dest", "description"], [
        [f"{DAY} 16:44:19", "AlertTriggered", "Device outside the country", "LT-0882",
         'Absolute alert rule "Device outside the country" triggered by DeviceExitedItsGeofence on LT-0882'],
        [f"{DAY} 15:02:51", "DeviceConnectionBlocked", "Device connection blocked: Inside restricted region",
         "WS-2231", "Absolute blocked the connection of WS-2231: Inside restricted region (Exampleland)"],
        [f"{DAY} 11:37:06", "AlertTriggered", "Encryption turned off", "LT-1507",
         'Absolute alert rule "Encryption turned off" triggered by DeviceBecameUnencrypted on LT-1507'],
    ])
    posture = table(["eventType", "count", "devices"], [
        ["DeviceExitedItsGeofence", "14", "9"], ["DeviceBecameAVProtected", "12", "12"],
        ["DeviceAVProductChanged", "7", "7"], ["APDeviceBecameCompliant", "5", "5"],
        ["DeviceBecameAVUnprotected", "3", "3"], ["APDeviceBecameNonCompliant", "2", "2"],
        ["DeviceBecameUnencrypted", "1", "1"]], num=(1, 2))
    oses = table(["os", "count"], [
        ["Microsoft Windows 11 Enterprise", "1,204"], ["Microsoft Windows 10 Enterprise", "498"],
        ["macOS 14", "92"], ["macOS 15", "41"], ["Chrome OS", "7"]], num=(1,))
    agents = table(["status", "encryption_status", "antivirus", "count"], [
        ["active", "Encrypted", "Example Antivirus", "1,688"], ["active", "Encrypted", "(none)", "71"],
        ["active", "Not Encrypted", "Example Antivirus", "38"], ["inactive", "Encrypted", "Example Antivirus", "33"],
        ["disabled", "(none)", "(none)", "12"]], num=(3,))
    body = (f'<div class="row"><div class="panel"><h3>Alerts (alert rules and blocked connections)</h3>{alerts}'
            f'</div></div>'
            f'<div class="row"><div class="panel"><h3>Security posture changes</h3>{posture}</div>'
            f'<div class="panel"><h3>Devices in the latest snapshot, by operating system</h3>{oses}</div>'
            f'<div class="panel"><h3>Agent, encryption and antivirus (latest snapshot)</h3>{agents}</div></div>')
    return page("Overview", "Overview",
                "What the Absolute data shows: SIEM event types, console activity, alerts, security posture "
                "changes, and the device inventory from the latest snapshot.",
                [("Time range", "Last 7 days"), ("Index (* = all)", "endpoint")], body)


INPUTS_PAGE = ui_test.PAGE.replace(
    "<style>body{font-family:Helvetica,Arial,sans-serif;margin:20px;color:#1d1f24}",
    "<style>" + CSS + " body{background:#fff;font-size:14px} #absolute-inputs-app{padding:16px 20px}"
    " body{font-family:Inter,Helvetica,Arial,sans-serif;color:#1d1f24}")
INPUTS_PAGE = INPUTS_PAGE.replace(
    "<body><div id=\"absolute-inputs-app\">",
    "<body>" + appbar("Inputs") + "<div id=\"absolute-inputs-app\">")
INPUTS_PAGE = INPUTS_PAGE.replace(
    "rows: [['events', 'abs-events', String(Date.now() / 1000 - 90), 'done',\n"
    "              'written 500, duplicates 50, excluded 0, api calls 2, window a to b, behind 5.0 min, 1.8 s', '5.0']]};",
    "rows: [['events', 'absolute_events', String(Date.now() / 1000 - 140), 'done',\n"
    "              'written 212, duplicates 187, excluded 0, api calls 1, window 2026-10-21T04:40:00.000Z to "
    "2026-10-21T04:50:00.000Z, behind 5.0 min, 0.7 s', '5.0'],\n"
    "             ['devices', 'absolute_devices', String(Date.now() / 1000 - 6 * 3600), 'done',\n"
    "              'devices 1842, pages 19, api calls 19, 31.8 MB, 148.2 s', null]]};")
assert "absolute_devices" in INPUTS_PAGE and LABEL in INPUTS_PAGE, "Inputs page template changed"
ui_test.PAGE = INPUTS_PAGE


def main():
    import http.server
    import threading
    from playwright.sync_api import sync_playwright
    web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ui_test.Server)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{web.server_port}/"
    shots = []
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": W, "height": H})
        for name, html in (("1-status", status_page()), ("2-overview", overview_page()),
                           ("3-overview-alerts-inventory", overview_page2())):
            pg.set_content(html)
            pg.wait_for_timeout(300)
            path = os.path.join(OUT, f"absolute-{name}.png")
            height = min(H, pg.evaluate("document.querySelector('.page').getBoundingClientRect().bottom") + 8)
            pg.screenshot(path=path, clip={"x": 0, "y": 0, "width": W, "height": height})
            shots.append(path)

        pg.goto(url)
        pg.wait_for_selector("#abs-input-rows")
        pg.wait_for_timeout(400)
        pg.click("text=Add account")
        pg.fill(".abs-modal input[name=name]", "absolute")
        pg.fill(".abs-modal input[name=api_host]", "api.absolute.com")
        pg.fill(".abs-modal input[name=token_id]", ui_test.fake.TOKEN_ID)
        pg.fill(".abs-modal input[name=token_secret]", ui_test.fake.SECRET)
        path = os.path.join(OUT, "absolute-5-add-account.png")
        pg.screenshot(path=path)
        shots.append(path)
        pg.click(".abs-modal-buttons .btn-primary")
        pg.wait_for_selector(".abs-modal", state="detached", timeout=60000)
        pg.wait_for_function("document.querySelector('.abs-flash').innerText.indexOf('Devices: OK') >= 0",
                             timeout=30000)

        pg.click("text=Add input")
        pg.fill(".abs-modal input[name=name]", "absolute_events")
        pg.fill(".abs-modal input[name=index]", "endpoint")
        pg.click(".abs-modal >> text=Advanced settings")
        pg.wait_for_timeout(200)
        path = os.path.join(OUT, "absolute-6-add-input.png")
        pg.screenshot(path=path)
        shots.append(path)
        pg.click(".abs-modal-buttons .btn-primary")
        pg.wait_for_selector(".abs-modal", state="detached", timeout=60000)

        pg.click("text=Add input")
        pg.select_option(".abs-modal select[name=kind]", "devices")
        pg.fill(".abs-modal input[name=name]", "absolute_devices")
        pg.fill(".abs-modal input[name=index]", "endpoint")
        pg.click(".abs-modal-buttons .btn-primary")
        pg.wait_for_selector(".abs-modal", state="detached", timeout=60000)
        pg.wait_for_timeout(900)
        pg.evaluate("document.querySelector('.abs-flash') && document.querySelector('.abs-flash').remove()")
        path = os.path.join(OUT, "absolute-4-inputs.png")
        bottom = pg.evaluate("document.querySelector('#abs-account-rows').getBoundingClientRect().bottom")
        pg.screenshot(path=path, clip={"x": 0, "y": 0, "width": W, "height": min(H, bottom + 40)})
        shots.append(path)
        b.close()
    ui_test.srv.close()
    for s in sorted(shots):
        print(s)


if __name__ == "__main__":
    main()
