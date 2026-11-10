# Splunkbase listing text — Nikhil Chawla Add-on for Absolute Secure Endpoint

For the 1.0.1 submission. Categories: Security, Fraud & Compliance; IT Operations (Endpoint).
Package: TA-absolute-secure-endpoint-1.0.1.tgz. Screenshots: absolute-1 to absolute-6 PNG (sample data only).

## Summary

```
Collects Absolute Secure Endpoint data from the Absolute API and maps it to the Splunk Common Information Model.

- SIEM events (sourcetype absolute:events): what devices report (applications installed, removed and updated; hardware, network, OS and user changes; location and geofence changes; encryption, antivirus and application-persistence status), what console users do (sign-ins, account and role changes, rules, geofences, policy groups, device freeze, disable and unenroll, location lookups), and alerts (alert rules that fired, connections blocked in restricted regions). The same events Absolute's SIEM Connector sends to a syslog server, read straight from the API, with each event's id and as JSON.
- Devices (sourcetype absolute:devices): an inventory snapshot, one event per device: hardware, OS, users, agent, addresses, encryption, antivirus, location.

CIM: Authentication, Change (Account_Management, Endpoint_Changes), Alerts, Data Access and Inventory. A saved search builds an Enterprise Security asset lookup from the device inventory.

- Inputs page in Splunk Web: Absolute accounts (API host, token ID and secret key, optional proxy; stored encrypted in Splunk's credential store; a Test button checks the token) and inputs: add, edit, enable, disable, run now, delete.
- SIEM events are collected from a checkpoint in overlapping windows and de-duplicated by event id: restarts and failures do not lose events. If Splunk stops a run part-way (input disabled or restarted), the next run continues from the checkpoint; at most the window it was cut off in is sent again.
- Status dashboard: last run, events and devices collected, minutes behind, errors, how late events arrive. Overview dashboard: event types, console activity, alerts, posture changes, devices by OS, agent, encryption and antivirus.
- Python standard library only, no third-party packages.

Independent project, not affiliated with or endorsed by Absolute Software. Absolute and Absolute Secure Endpoint are trademarks of Absolute Software Corporation.
```

## Short description

```
Collects Absolute Secure Endpoint SIEM events (device, console and alert activity) and device inventory from the Absolute API, with CIM mappings (Authentication, Change, Alerts, Data Access, Inventory) and an ES asset lookup. Accounts, inputs and status are managed in Splunk Web. Independent project, not affiliated with Absolute Software.
```

## Installation

```
Requirements
- Splunk Enterprise 9.x or 10.x heavy forwarder for the inputs; the add-on on the search heads too (no inputs there) for the CIM mappings and dashboards.
- HTTPS (443) from the forwarder to the Absolute API host (api.absolute.com or your region's), directly or through an HTTP proxy.
- An Absolute API token (Absolute console: Settings > API management) with read access to SIEM events and device reporting. If the token only allows certain IP addresses, allow the forwarder's public address.

In Splunk
1. Install the add-on on the heavy forwarder and restart Splunk. Install it on the search heads as well.
2. Create the index the inputs will write to.
3. Open the add-on > Inputs > Add account: name (the events' host), API host, token ID, secret key. Saving tests the token.
4. Add input > SIEM events (every 5 minutes; the first run starts 24 hours back) and Add input > Devices (daily; devices that connected in the last 24 hours).
5. Check the Status dashboard.
6. Optional, Enterprise Security: set the absolute_index macro, enable the saved search "Absolute - Asset lookup", and add the absolute_assets lookup as an asset source.
```

## Troubleshooting

```
Each input logs every run to $SPLUNK_HOME/var/log/splunk/absolute_se_<events|devices>_<input>.log (index _internal, sourcetype absolute:ta:log): "run done: ...", "run failed: <reason>", "run skipped: <reason>" or "run stopped: <reason>" (Splunk stopped the run; the next one continues from the checkpoint).

- HTTP 401 ... not accepted: wrong token ID or secret key, or the token was deleted or disabled. Edit the account; Test shows the result.
- HTTP 403: the token lacks read access to SIEM events or device reporting, or allows only other IP addresses.
- cannot reach the API host: DNS, firewall or proxy; set the account's proxy if needed.
- TLS certificate could not be verified: a TLS-inspecting proxy; add its CA to the forwarder's system CA bundle.
- Device events missing JSON fields: Splunk extracts JSON from the first 10240 characters by default ([kv] maxchars); the add-on puts the common fields first; use spath for the rest.
- SIEM events arrive late: Absolute records a device's events when it next connects; _time is when the event happened. Search on index time for complete coverage of a period.
```

## Release notes (1.0.1)

```
- A run that Splunk stops (input disabled, edited or restarted, Run now, or Splunk stopping) now ends cleanly with "run stopped" instead of failing with BrokenPipeError, and keeps its checkpoint. If Splunk had already closed the pipe, the window that was cut short is sent again, so no events are lost.
- An event is marked as sent only once it has been written.
- Run now is refused while a run of that input is in progress.
```

## AppInspect notes (for the submission)

```
AppInspect 1.0.1: 0 failures, 0 errors (Splunkbase and cloud tags). Warnings, no action needed:
- check_for_modular_inputs: the add-on's two modular inputs (absolute_events, absolute_devices).
- check_for_splunk_js: the Inputs page uses SplunkJS (informational telemetry warning).
- check_for_python_script_existence: Python 3 only (python.version = python3 everywhere).
- check_for_indexer_synced_configs: default/inputs.conf (both inputs disabled by default) is for the heavy forwarder, not indexers.
- check_for_updates_disabled: check_for_updates stays true because the add-on is distributed through Splunkbase.
```
