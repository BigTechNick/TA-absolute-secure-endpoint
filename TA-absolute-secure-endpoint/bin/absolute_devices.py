#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
absolute_devices.py - modular input "absolute_devices": Absolute device
inventory (/v3/reporting/devices-advanced) into Splunk, sourcetype
absolute:devices. One event per device per run (a snapshot); all events of
one run have the same _time.

  * connected_within_hours: only devices that connected in the last N hours
    (0 = every device in the account, retired ones included).
  * A run that Splunk starts again soon after the last complete one (for
    example when Splunk restarts) is skipped unless "Run now" was chosen on
    the Inputs page, so a restart does not index the inventory twice.
  * Keys are reordered so the fields most searches use (names, users, OS,
    addresses, agent, encryption, antivirus, location) come first: Splunk
    extracts JSON fields at search time from the first 10240 characters of an
    event by default (limits.conf [kv] maxchars), and device records can be
    longer. Nothing is changed or dropped unless exclude_fields says so.
"""
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import absolute_se_api as api  # noqa: E402
import absolute_se_modinput as mi  # noqa: E402
import absolute_se_store as store  # noqa: E402

KIND = "devices"
SCHEME = store.SCHEMES[KIND]
SOURCETYPE = "absolute:devices"
SKIP_SHARE = 0.9                   # skip a run within 90% of the interval after the last complete one

ARGS = [
    ("account", "Absolute account",
     "Name of the Absolute account (API host and token) saved on the add-on's Inputs page.", "string", True),
    ("connected_within_hours", "Devices connected within (hours)",
     "Only devices that connected to Absolute in the last N hours (0 = every device in the account, retired "
     "ones included; 0-87600). Default 24.", "number", False),
    ("page_size", "Page size",
     "Devices per API call (1-1000, or 0 for the API's own default of 10). Default 100.", "number", False),
    ("exclude_fields", "Leave out fields",
     "Comma-separated top-level fields not to index, e.g. printers,usbs,keyboards,pointingDevices,sounds,"
     "cameras,cdRoms,displays. Default: none.", "string", False),
    ("log_level", "Log level", "DEBUG, INFO, WARNING or ERROR. Default INFO.", "string", False),
]

FIRST = (
    "deviceUid", "deviceName", "fullSystemName", "domain", "serialNumber", "esn", "systemManufacturer",
    "systemModel", "systemType", "chassisType", "platformOSType", "operatingSystem", "username",
    "currentUsername", "agentStatus", "agentVersion", "persistentAgentVersion", "isStolen",
    "lastConnectedDateTimeUtc", "lastUpdatedDateTimeUtc", "firstCallDateTimeUtc", "unenrollmentDateTimeUtc",
    "localIp", "publicIp", "currentNetworkName", "policyGroupName", "policyGroupUid", "deviceGroupIds",
    "orgUnits", "customFields", "cpu", "totalPhysicalRamBytes", "availablePhysicalRamBytes", "espInfo",
    "avpInfo", "geoData", "deviceFreezeStatus", "latestEvent", "networkAdapters", "volumes",
)


def shape(record, exclude):
    out = {}
    for key in FIRST:
        if key in record and key not in exclude:
            out[key] = record[key]
    for key, value in record.items():
        if key not in out and key not in exclude:
            out[key] = value
    return out


def interval_seconds(params):
    value = str(params.get("interval") or "").strip()
    return int(value) if re.fullmatch(r"\d+", value) else None


def run(cfg, name, params):
    level = (params.get("log_level") or "INFO").upper()
    log = mi.setup_logging(KIND, name, level)
    checkpoint_dir = cfg.get("checkpoint_dir") or store.state_root(SCHEME)
    lock = mi.RunLock(store.lock_path(SCHEME, name, checkpoint_dir))
    if not lock.acquire():
        log.info("run skipped: the previous run of this input is still going")
        return 0
    state_file = store.state_path(SCHEME, name, checkpoint_dir)
    marker = store.run_now_path(SCHEME, name, checkpoint_dir)
    state = mi.load_json(state_file, {})
    now = time.time()
    interval = interval_seconds(params)
    last = state.get("last_success") if isinstance(state.get("last_success"), (int, float)) else None
    if os.path.exists(marker):
        try:
            os.remove(marker)
        except OSError:
            pass
        log.info("run requested on the Inputs page")
    elif last and interval and now - last < interval * SKIP_SHARE:
        log.info("run skipped: the last complete run was %.0f min ago (interval %d min); next one at %s UTC",
                 (now - last) / 60, interval // 60, time.strftime("%Y-%m-%d %H:%M", time.gmtime(last + interval)))
        return 0

    stop = mi.Stopper()
    out = mi.EventStream()
    count = 0
    client = None
    try:
        account_name = params["account"]
        account = store.Accounts(store.Splunkd(cfg["session_key"])).get(account_name)
        client = store.client_for(account, log=log, should_stop=stop)
        hours = store.number(params, KIND, "connected_within_hours")
        since = now - hours * 3600 if hours else None
        page_size = store.number(params, KIND, "page_size")
        exclude = set(store.comma_list(params.get("exclude_fields")))
        log.info("run started: account %s (%s), %s, page size %s", account_name, account["api_host"],
                 f"devices connected since {api.utc_text(since)}" if since else "every device in the account",
                 page_size or "API default")
        pages = 0
        for records, page in api.device_pages(client, since, page_size):
            pages = page
            for record in records:
                if stop():
                    break
                out.write(shape(record, exclude), now, SOURCETYPE, account_name)
                count += 1
            out.flush()
            if stop():
                log.warning("run stopped: stopped by Splunk (input disabled or restarted, or Splunk stopping) "
                            "after %d devices; the next run starts over", count)
                return 0
        mi.save_json(state_file, {"last_success": time.time(), "last_count": count, "account": account_name})
        log.info("run done: devices %d, pages %d, api calls %d, %.1f MB, %.1f s", count, pages, client.calls,
                 out.bytes / 1048576.0, time.time() - now)
        return 0
    except mi.OutputClosed:
        log.warning("run stopped: Splunk stopped reading this input's events (input disabled or restarted, or "
                    "Splunk stopping) after %d devices; the next run starts over", count)
        return 0
    except api.ApiError as exc:
        if str(exc) == "stopped":
            log.warning("run stopped: stopped by Splunk (input disabled or restarted, or Splunk stopping) "
                        "after %d devices; the next run starts over", count)
            return 0
        log.error("run failed: %s (%d devices sent before the error)", exc, count)
        return 1
    except store.StoreError as exc:
        log.error("run failed: %s", exc)
        return 1
    except Exception as exc:
        log.exception("run failed: %s: %s", type(exc).__name__, exc)
        return 1
    finally:
        out.close()


if __name__ == "__main__":
    mi.main(KIND, "Absolute devices",
            "Absolute Secure Endpoint device inventory (hardware, OS, agent, encryption, antivirus, location) "
            "from the Absolute API.", ARGS, run)
