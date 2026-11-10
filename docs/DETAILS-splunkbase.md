## What it collects

| Sourcetype | Absolute API | What |
|---|---|---|
| `absolute:events` | `/v3/reporting/siem-events` | SIEM events, one per Absolute event, as JSON: what devices report (applications installed, removed and updated; hardware, network, OS and user changes; location and geofence changes; encryption, antivirus and application-persistence status), what console users do (sign-ins, account and role changes, rules, geofences, policy groups, device freeze, disable and unenroll, location lookups), and alerts (alert rules that fired, connections blocked in restricted regions). The same events Absolute's SIEM Connector sends, read straight from the API. |
| `absolute:devices` | `/v3/reporting/devices-advanced` | Device inventory snapshot, one event per device per run: hardware, OS, users, agent, addresses, encryption, antivirus, location. |

## Where to install

| Splunk instance | Install? | Why |
|---|---|---|
| Heavy forwarder | Yes | Runs the inputs and parses the data. |
| Search heads (including Splunk Cloud and Enterprise Security) | Yes | Field extractions, event types, tags, CIM mappings, dashboards. Do not configure inputs there. |
| Indexers | No | The heavy forwarder parses the data. |

## Set up

1. In the Absolute console, create an API token (Settings > API management) with read access to SIEM events and device reporting. If the token only allows certain IP addresses, add the forwarder's public address.
2. Create the index the inputs will write to (the add-on creates no indexes).
3. On the heavy forwarder, open the add-on > **Inputs** > **Add account**: a name (it becomes the events' `host`), the API host (`api.absolute.com` or your regional host), the token ID and secret key, and a proxy only if needed. Saving tests the token: *SIEM events: OK; Devices: OK*. The secret is stored encrypted in Splunk's credential store.
4. **Add input** > **SIEM events**: name, account, index. Defaults: every 5 minutes; the first run starts 24 hours back.
5. **Add input** > **Devices**: name, account, index. Defaults: daily; devices that connected in the last 24 hours.
6. Open the **Status** dashboard: each input shows *OK* after its first run.

## How the inputs work

**SIEM events**

* Each run reads the events Absolute recorded since the previous run, up to *Delay* minutes ago (default 5), in windows of up to an hour.
* Each window overlaps the previous one by *Overlap* minutes (default 10), and events already sent are skipped by their `id`, so events Absolute records a little late are still collected.
* A checkpoint is saved after every window: after a restart or an error, the next run continues from it, and no events are lost.
* `_time` is when the event happened (`eventDateTimeUtc`). Devices that were offline report their events when they reconnect, sometimes days later; for complete coverage of a period, search on index time (`_index_earliest`).
* `objectProperties` is also split into fields: `properties.<name>.old` and `properties.<name>.new`.
* Settings: *First run: hours back* (up to 720), *Leave out event types*, *Delay*, *Overlap*, *Page size*, *Log level*.

**Devices**

* One event per device per run, all with the run's start as `_time`. Use `| dedup deviceUid` for the latest state of each device.
* *Devices connected within (hours)*: 0 collects every device in the account, retired ones included.
* A run that starts soon after the last complete one (for example after a Splunk restart) is skipped, so the inventory is not indexed twice. *Run now* on the Inputs page runs it anyway.
* *Leave out fields* (or the *Leave out peripherals* option) drops large fields such as printers and USB devices to save license.
* Device records can be longer than Splunk's automatic JSON extraction reads by default (100 fields, 10240 characters). The CIM fields are always extracted; for other fields use `| spath`.

## CIM mapping

| Event type | Covers | CIM data model | Tags |
|---|---|---|---|
| `absolute_authentication` | console sign-ins | Authentication | authentication |
| `absolute_account_change` | console accounts created, changed or reset | Change (Account_Management) | change, account |
| `absolute_console_change` | console settings: roles, rules, geofences, policy groups, approvals | Change | change |
| `absolute_endpoint_change` | everything reported by a device or done to it | Change (Endpoint_Changes) | change, endpoint |
| `absolute_alert` | alert rules that fired, blocked connections | Alerts | alert |
| `absolute_data_access` | console users viewing location history or the map | Data Access | data, access |
| `absolute_device` | device inventory snapshots | Inventory | inventory, cpu, memory, network, storage, system, version |

Main fields: `vendor_product`, `dest`, `user`, `src`, `action`, `status`, `object`, `object_category`, `change_type`, `signature`, `severity`; for devices `dest_nt_host`, `serial`, `os`, `ip`, `mac`, `cpu_count`, `mem`.

## Dashboards

* **Status**: last run per input, events and devices collected, minutes behind, errors and warnings, how late events arrive, Splunk's messages about the inputs, and changes made on the Inputs page.
* **Overview**: SIEM events by type and over time, console activity, alerts, security posture changes, devices by operating system, agent, encryption and antivirus.

## Enterprise Security assets

The saved search **Absolute - Asset lookup** (disabled by default) builds the lookup `absolute_assets` in Enterprise Security's asset format from the latest device snapshot. Set the `absolute_index` macro to your index, enable the saved search, and add `absolute_assets` under Enterprise Security > Configure > Data Enrichment > Asset and Identity Management.

## Example searches

```
index=<your index> sourcetype="absolute:events" | stats count by eventType | sort - count
index=<your index> sourcetype="absolute:events" tag=authentication | stats count by user, src, action
index=<your index> sourcetype="absolute:events" tag=alert | table _time signature dest description
index=<your index> sourcetype="absolute:devices" | dedup deviceUid | stats count by os
```

## Logs

Each input logs every run to `$SPLUNK_HOME/var/log/splunk/absolute_se_<events|devices>_<input>.log` (index `_internal`, sourcetype `absolute:ta:log`), ending with *run done*, *run failed*, *run skipped* or *run stopped*:

```
index=_internal sourcetype="absolute:ta:log" ("run done" OR "run failed" OR "run stopped")
```

## Moving from Absolute's SIEM Connector

1. Add the account and a SIEM events input with *First run: hours back* covering the time since the connector last sent.
2. Compare a day of data from both, then stop the connector and delete its API token in the Absolute console.

## Support

Community-supported, best effort, through this Splunkbase page. Independent project, not affiliated with or endorsed by Absolute Software. Absolute and Absolute Secure Endpoint are trademarks of Absolute Software Corporation.
