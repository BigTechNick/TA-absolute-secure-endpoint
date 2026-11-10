# Nikhil Chawla Add-on for Absolute Secure Endpoint

Version 1.0.1. App ID (folder name): `TA-absolute-secure-endpoint`.

Collects data from the Absolute API (Absolute Secure Endpoint) and maps it to
the Splunk Common Information Model (CIM):

* **SIEM events** (`/v3/reporting/siem-events`), sourcetype `absolute:events`:
  what devices report (applications installed, removed and updated; hardware,
  network, OS and user changes; location and geofence changes; encryption,
  antivirus and application-persistence status), what console users do
  (sign-ins, account and role changes, rules, geofences, policy groups, device
  freeze / disable / unenroll, location lookups), and alerts (alert rules that
  fired, connections blocked in restricted regions). The same events Absolute's
  own SIEM Connector sends, read straight from the API.
* **Devices** (`/v3/reporting/devices-advanced`), sourcetype `absolute:devices`:
  an inventory snapshot, one event per device (hardware, OS, users, agent,
  addresses, encryption, antivirus, location, application-persistence status).

> Independent project, not affiliated with or endorsed by Absolute Software.
> Absolute and Absolute Secure Endpoint are trademarks of Absolute Software
> Corporation. See NOTICE.

Everything is managed in Splunk Web:

* **Inputs** page: Absolute accounts (API host, token ID and secret key,
  optional proxy; stored encrypted in Splunk's credential store; a *Test*
  button checks the token against the API) and the inputs that use them: add,
  edit, enable/disable, run now, delete.
* **Status** dashboard: last run, events and devices collected, minutes
  behind, errors, how late events arrive, Splunk's own messages about the
  inputs, and changes made on the Inputs page.
* **Overview** dashboard: event types, console activity, alerts, security
  posture changes, and devices by OS, agent, encryption and antivirus.

## Requirements

* Splunk Enterprise 9.x or 10.x heavy forwarder (tested on Linux). Runs on
  Splunk's bundled Python (3.13 where available, else 3.9) with the standard
  library only: no third-party packages.
* Network: HTTPS (TCP 443) from the forwarder to the Absolute API host
  (`api.absolute.com`, or the regional host that matches the Absolute console
  you sign in to), directly or through an HTTP proxy. The certificate is
  always verified (system CAs and the CA bundle that ships with Splunk). The
  add-on opens no listening ports.
* An Absolute API token (Absolute console: Settings > API management) with read
  access to SIEM events and to device reporting data. If the token only allows
  certain IP addresses, allow the forwarder's public address.
* Search heads: this add-on, for the field extractions, CIM mappings and
  dashboards (no inputs there).

## Install

1. Heavy forwarder: install the add-on (Apps > Manage Apps > Install app from
   file, or untar into `$SPLUNK_HOME/etc/apps`) and restart Splunk.
2. Search heads (Splunk Cloud: install it as an app): the same package, with no
   inputs. Index-time settings (line breaking, timestamps) apply on the
   forwarder, where the data is parsed.
3. Create the index the inputs will write to (the add-on creates no indexes).

## Set up

1. Open the add-on and go to **Inputs**.
2. **Add account**: a name (it becomes the events' `host` field), the API host,
   the token ID and the secret key, and a proxy only if the forwarder needs one.
   The account is tested when it is saved: *SIEM events: OK; Devices: OK*.
3. **Add input**, type **SIEM events**: name, account, index. Defaults: every
   5 minutes; the first run starts 24 hours back.
4. **Add input**, type **Devices**: name, account, index. Defaults: daily;
   devices that connected in the last 24 hours. *Leave out peripherals* drops
   printers, USB controllers, keyboards, mice, sound devices, cameras, CD drives
   and displays from each record to save license.
5. Watch **Status**: each input shows *OK* after its first run.

## SIEM events (`absolute:events`)

* One event per Absolute event: Absolute's JSON record as the API returns it
  (`id`, `eventType`, `verb`, `actorObjectType`, `actorDisplayName`,
  `actorDisplayId`, `objectObjectType`, `objectDisplayName`, `objectDisplayId`,
  `objectProperties`, `secondaryObjectType`, `secondaryObjectDisplayName`,
  `secondaryObjectDisplayId`, `createdDateTimeUtc`, `eventDateTimeUtc`), plus
  `properties`: `objectProperties` split up, one field per property:
  `properties.<name>.old` and `properties.<name>.new` (for example
  `properties.IpAddress.new`, `properties.Latitude.new`). A property name that
  repeats the event type (`DeviceNetworkAdapterUpdated.IpV4Address`) is shortened
  (`IpV4Address`). Empty values are left out.
* `_time` = `eventDateTimeUtc`, when it happened on the device or in the
  console. Absolute records events from a device when the device next connects,
  so events from devices that were offline arrive late, sometimes days late
  (the Status dashboard shows how late). Searches that must see every event
  indexed in a period (correlation searches, for example) should select on
  index time (`_index_earliest`) or use a wide enough `earliest`.
* `host` = the account name.

How it collects:

* Each run asks the API for the events Absolute recorded (`createdDateTimeUtc`)
  in a time window: from where the previous run ended to *Delay* minutes ago
  (default 5), in windows of at most an hour, page by page (*Page size*,
  default 1000).
* Each window starts *Overlap* minutes (default 10) before the previous one
  ended, and events already sent are recognised by their `id` and skipped, so an
  event Absolute records a little late is still collected and nothing is sent
  twice.
* The checkpoint (end of the last complete window, ids of recent events) is
  saved after every window, in `$SPLUNK_DB/modinputs/absolute_events/<input>.json`
  (`$SPLUNK_DB` is usually `$SPLUNK_HOME/var/lib/splunk`). After a failure or a
  restart, the next run continues from there.
* When Splunk stops a run (the input is disabled, edited or restarted, or
  Splunk stops), the run ends at once and logs *run stopped*. If Splunk had
  already closed the pipe it reads events from, events still on their way may
  not have arrived, so the next run sends that window again: some of its events
  may then be indexed twice, none are lost.
* *First run: hours back* (default 24, up to 720): where a new input starts.
* *Leave out event types*: event types not to index (for example
  `ApplicationUpdated`).
* Rate limits, server errors and network errors (HTTP 408, 425, 429, 500, 502,
  503, 504, timeouts, dropped connections) are retried up to 5 times with
  backoff, following `Retry-After`. Other errors end the run; the next run
  tries again from the checkpoint, and events sent before the error are not
  sent again.

Volume: the event rate depends on the fleet; around a thousand bytes per event.

## Devices (`absolute:devices`)

* One event per device per run: Absolute's JSON record as the API returns it,
  with the same `_time` (the run's start) for the whole snapshot. Use
  `| dedup deviceUid` for the latest state of each device.
* *Devices connected within (hours)* (default 24): only devices that connected
  in that time; 0 = every device in the account, retired ones included.
* A run that Splunk starts within 90% of the interval after the last complete
  run (for example when Splunk restarts) is skipped, so a restart does not
  index the inventory twice. *Run now* on the Inputs page runs it anyway (right
  away when the interval is in seconds; at the next scheduled time with a cron
  schedule).
* Records are often 5-20 KB with a few hundred fields. Splunk's automatic JSON
  field extraction stops after 100 fields and 10240 characters by default
  (`limits.conf` `[kv] limit` and `maxchars` on the search heads). The CIM
  fields are read with `spath()`, which reads the whole record, so they are
  always there. For other fields, the add-on puts the ones most searches use
  first (names, users, OS, agent, addresses, policy group, CPU, memory,
  encryption, antivirus, location); fields further back can be read with
  `| spath`, or by raising those limits. Nothing in the record is changed.
* *Leave out fields*: top-level fields not to index (for example printers and
  other peripherals).
* *Page size* (default 100; 0 = the API's own default of 10).

## CIM mapping

| Event type (eventtype) | Events | CIM data model | Tags |
|---|---|---|---|
| `absolute_authentication` | `UserLogin` | Authentication | authentication |
| `absolute_account_change` | changes to console accounts (`UserCreated`, `UserUpdated`, `TwoFactorAuthUserReset`, ...) | Change: Account_Management | change, account |
| `absolute_console_change` | console settings: roles, rules, geofences, policy groups, approvals | Change | change |
| `absolute_endpoint_change` | everything about a device: reported by its agent or done to it (freeze, disable, unenroll, license, policy group) | Change: Endpoint_Changes | change, endpoint |
| `absolute_alert` | `AlertTriggered`, `DeviceConnectionBlocked` | Alerts | alert |
| `absolute_data_access` | console users viewing location history or the map | Data Access | data, access |
| `absolute_device` | device inventory snapshots | Inventory (All_Inventory, CPU, Memory, Network, Storage, OS) | inventory, cpu, memory, network, storage, system, version |
| `absolute_session` | `UserLogout`, `SessionTimeout` (not CIM-mapped) | | |

New device event types are covered by `absolute_endpoint_change` without an
update. Fields:

* All events: `vendor` (Absolute), `product` (Secure Endpoint),
  `vendor_product`, `dvc` (= host), `app` (`absolute:console` for console
  users, `absolute:agent` for devices).
* `dest`: the device the event is about; for console events and location
  lookups, the account (host).
* `user`: the console user who acted; for account changes the account changed,
  with `src_user` = who changed it. `src` and `user_agent`: from the sign-in's
  IP address and browser.
* `action`: Installed, Added, Created, Enrolled = `created`; Uninstalled,
  Removed, Deleted = `deleted`; DeviceDisabled = `stopped`; Accessed = `read`;
  sign-in = `success`; sign-out and time-out = `logoff`; everything else
  `modified`. `status` = `failure` for failed events, else `success`.
  `result` = Absolute's `verb`.
* `object`, `object_id`, `object_category`: what changed (for volumes, disks,
  network adapters and policy groups the secondary object; otherwise the
  object). `object_attrs`: the names of the properties that changed.
  `change_type`: application, application_persistence, geolocation,
  encryption, antivirus, agent, hardware, inventory, device_management,
  configuration, AAA or other.
* Alerts: `signature` (the alert rule, or why a connection was blocked),
  `signature_id`, `description`, `severity` = medium, `type` = alert, `id`.
* Devices: `dest`, `dest_nt_host`, `dest_dns`, `serial`, `vendor_product`
  (manufacturer and model), `os`, `version`, `family`, `cpu_count`,
  `cpu_cores`, `cpu_mhz`, `mem` (MB; older agents report MB), `ip`, `mac`
  (lowercase, colon-separated), `interface`, `mount`, `status`
  (active / inactive / disabled), `enabled`, `user`, `description`
  (policy group).

## Enterprise Security assets

The saved search **Absolute - Asset lookup** (disabled) writes the lookup
`absolute_assets` in Enterprise Security's asset format (ip, mac, nt_host, dns,
owner, lat, long, city, country, category, ...) from the latest device
snapshot. To use it: set the `absolute_index` macro to your index (for example
`index=endpoint`), enable the saved search, and add `absolute_assets` in
Enterprise Security > Configure > Data Enrichment > Asset and Identity
Management.

## Files and logs

| Path | What |
|---|---|
| `bin/absolute_events.py`, `bin/absolute_devices.py` | the two modular inputs |
| `bin/absolute_se_api.py` | Absolute API client (signed requests, paging, retries) |
| `bin/absolute_se_modinput.py` | what both inputs share (scheme, validation, logging, output) |
| `bin/absolute_se_store.py` | accounts in the credential store, settings, status |
| `bin/absolute_se_rest.py` | REST API for the Inputs page |
| `$SPLUNK_DB/modinputs/absolute_events/<input>.json` | SIEM events checkpoint |
| `$SPLUNK_DB/modinputs/absolute_devices/<input>.json` | last complete devices run |
| `$SPLUNK_HOME/var/log/splunk/absolute_se_<events or devices>_<input>.log` | each run (index _internal, sourcetype `absolute:ta:log`); 10 MB, 3 old copies |
| `$SPLUNK_HOME/var/log/splunk/absolute_se-webapi.log` | changes made on the Inputs page (sourcetype `absolute:ta:webapi`) |

Every run ends with one line:

`run done: written 500, duplicates 50, excluded 0, api calls 1, window 2026-01-01T12:00:00.000Z to 2026-01-01T12:05:00.000Z, behind 5.0 min, 1.0 s`

`run done: devices 1000, pages 10, api calls 10, 15.0 MB, 30.0 s`

or `run failed: <reason>`, or `run skipped: <reason>`.

## Moving from Absolute's SIEM Connector

The SIEM events input reads the same events the SIEM Connector sends to a
syslog server, from the same API, with each event's `id` and as JSON instead
of syslog lines. To move:

1. Add the account and a SIEM events input with *First run: hours back*
   covering the time since the connector last sent (up to 720 hours).
2. Compare a day in both, then stop the connector's service and delete its API
   token in the Absolute console.

## Troubleshooting

Start with the input's log (`absolute_se_<kind>_<input>.log`) or the Status
dashboard.

* *HTTP 401 ... not accepted*: wrong token ID or secret key, or the token was
  deleted or disabled. Edit the account; *Test* shows the result.
* *HTTP 403*: the token lacks read access to SIEM events or device reporting,
  or allows only other IP addresses.
* *cannot reach api.absolute.com*: DNS, firewall or proxy. Set the account's
  proxy if the forwarder needs one.
* *TLS certificate ... could not be verified*: a proxy that inspects TLS; add
  its CA to the forwarder's system CA bundle.
* Status *LATE*: the input has not run recently. Check the panel "Splunk
  messages about the inputs".
* Status *BEHIND*: the last window ended more than an hour ago; the input is
  catching up, or its runs keep failing.
* Devices: *run skipped: the last complete run was ...*: expected after a
  restart; use *Run now* to collect anyway.
* *Run now* restarts the input, so it is refused while a run of that input is
  in progress (*a run of input ... is in progress*). Try again when it has
  finished.
* *run stopped*: Splunk stopped the run (input disabled, edited or restarted,
  or Splunk stopping). The next run continues from the checkpoint.
* JSON fields missing on device events: see "Devices" above (`[kv] limit` and
  `maxchars`); the CIM fields are not affected.

## Changes

* 1.0.1: A run that Splunk stops (input disabled, edited or restarted) ends
  cleanly and logs *run stopped* instead of failing with *BrokenPipeError*; the
  checkpoint is kept, and if Splunk closed the pipe first the window is sent
  again so no events are lost. An event is marked as sent only once it is
  written. *Run now* is refused while a run is in progress.
* 1.0.0: First release: SIEM events and device inputs, Inputs page with
  account test, Status and Overview dashboards, CIM mappings, Enterprise
  Security asset lookup.

## License and support

Apache License 2.0 (see LICENSE and NOTICE). Copyright 2026 Nikhil Chawla.
Community-supported, best effort, through the add-on's Splunkbase page; no
warranty.
