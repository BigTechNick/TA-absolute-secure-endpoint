[absolute_events://<name>]
* Absolute Secure Endpoint SIEM events (device, console and alert activity) from the
  Absolute API (/v3/reporting/siem-events), indexed as sourcetype absolute:events.
* <name>: letters, digits, '.', '_' or '-' (max 64), starting with a letter or digit;
  unique across both kinds of input of this add-on.
* Created and edited in Splunk Web: the add-on's Inputs page (or Settings > Data inputs).
* Each run collects the events Absolute recorded since the previous run's window ended,
  up to delay_minutes ago, and saves its place (checkpoint) after every window of at
  most an hour: $SPLUNK_HOME/var/lib/splunk/modinputs/absolute_events/<name>.json.
* interval: seconds between runs (or a cron schedule). Default 300.

account = <string>
* Required. Name of the Absolute account (API host, token ID, secret key, optional
  proxy) saved on the add-on's Inputs page. Stored encrypted in the credential store
  (storage/passwords, realm absolute_se_account).

start_hours_ago = <integer>
* How far back the first run starts, in hours (0-720). 0: from now on.
* Default: 24

delay_minutes = <integer>
* Each window ends this many minutes before now, so Absolute has finished recording
  its events (0-120).
* Default: 5

overlap_minutes = <integer>
* Each window starts this many minutes before the previous one ended. Events already
  sent are recognised by their id and skipped (0-120).
* Default: 10

page_size = <integer>
* Events per API call (1-1000).
* Default: 1000

exclude_event_types = <string>
* Comma-separated eventType names not to index, for example ApplicationUpdated.
* Default: empty (all event types)

log_level = DEBUG|INFO|WARNING|ERROR
* Level of $SPLUNK_HOME/var/log/splunk/absolute_se_events_<name>.log.
* Default: INFO

[absolute_devices://<name>]
* Absolute Secure Endpoint device inventory from the Absolute API
  (/v3/reporting/devices-advanced), indexed as sourcetype absolute:devices: one event
  per device per run, all with the run's start time.
* <name>: as for absolute_events.
* A run that starts within 90% of the interval after the last complete run (for
  example when Splunk restarts) is skipped, unless "Run now" was chosen on the
  Inputs page.
* interval: seconds between runs (or a cron schedule). Default 86400 (daily).

account = <string>
* Required. As for absolute_events.

connected_within_hours = <integer>
* Only devices that connected to Absolute in the last N hours (0-87600).
  0: every device in the account, retired ones included.
* Default: 24

page_size = <integer>
* Devices per API call (1-1000), or 0 for the API's own default (10).
* Default: 100

exclude_fields = <string>
* Comma-separated top-level fields of the device record not to index, for example
  printers,usbs,keyboards,pointingDevices,sounds,cameras,cdRoms,displays.
  deviceUid and deviceName cannot be left out.
* Default: empty (all fields)

log_level = DEBUG|INFO|WARNING|ERROR
* Level of $SPLUNK_HOME/var/log/splunk/absolute_se_devices_<name>.log.
* Default: INFO
