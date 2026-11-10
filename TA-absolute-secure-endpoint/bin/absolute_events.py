#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
absolute_events.py - modular input "absolute_events": Absolute SIEM events
(/v3/reporting/siem-events) into Splunk, sourcetype absolute:events.

Each run (every `interval` seconds) asks for the events Absolute recorded
since the end of the previous run's window, up to a few minutes ago (delay),
in windows of at most an hour, page by page:

  * The window is on the time Absolute recorded the event (createdDateTimeUtc).
    A device that was offline reports days-old events late; they are still
    collected, with _time = when they happened (eventDateTimeUtc).
  * Each window starts `overlap` minutes before the previous one ended, and
    events already sent are recognised by their id and skipped.
  * The checkpoint (end of the last completed window, ids of recent events)
    is saved after every window: $SPLUNK_HOME/var/lib/splunk/modinputs/
    absolute_events/<input>.json.
  * First run: from start_hours_ago hours back.
  * When Splunk stops a run (input disabled, edited or restarted), it ends at
    once ("run stopped"). If splunkd had already closed the pipe, events on
    their way may not have arrived, so only the ids of complete windows are
    kept and the next run sends the cut-short window again.

Each event is Absolute's JSON record, plus "properties": objectProperties
split into {name: {"old": ..., "new": ...}}.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import absolute_se_api as api  # noqa: E402
import absolute_se_modinput as mi  # noqa: E402
import absolute_se_store as store  # noqa: E402

KIND = "events"
SCHEME = store.SCHEMES[KIND]
SOURCETYPE = "absolute:events"
MAX_WINDOW = 3600                  # seconds per window (the checkpoint is saved after each)
# Ids of events sent are kept this long after their window (the largest overlap, plus 2 minutes),
# so a larger overlap set later still recognises them.
SEEN_KEEP = 122 * 60

ARGS = [
    ("account", "Absolute account",
     "Name of the Absolute account (API host and token) saved on the add-on's Inputs page.", "string", True),
    ("start_hours_ago", "First run: hours back",
     "How far back the first run starts (0-720). Default 24.", "number", False),
    ("delay_minutes", "Delay (minutes)",
     "Each window ends this many minutes before now, so Absolute has finished recording its events (0-120). "
     "Default 5.", "number", False),
    ("overlap_minutes", "Overlap (minutes)",
     "Each window starts this many minutes before the previous one ended; events already sent are skipped "
     "by id (0-120). Default 10.", "number", False),
    ("page_size", "Page size", "Events per API call (1-1000). Default 1000.", "number", False),
    ("exclude_event_types", "Leave out event types",
     "Comma-separated eventType names not to index, e.g. ApplicationUpdated. Default: none.", "string", False),
    ("log_level", "Log level", "DEBUG, INFO, WARNING or ERROR. Default INFO.", "string", False),
]


def resume_point(state, start):
    """Where the next run picks up: the end of the last complete window, or a first run's start."""
    return state.get("end") or (api.utc_text(start) if start is not None else "the first run's start")


def created_of(record, fallback):
    return api.parse_utc(record.get("createdDateTimeUtc")) or fallback


def shape(record):
    """
    Absolute's record, plus objectProperties as a dict ("properties"). objectProperties and
    properties go last: they can be long, and Splunk's automatic JSON extraction reads the first
    10240 characters of an event by default.
    """
    out = {k: v for k, v in record.items() if k != "objectProperties"}
    if "objectProperties" in record:
        out["objectProperties"] = record["objectProperties"]
    props = api.parse_properties(record.get("objectProperties"), record.get("eventType") or "")
    if props:
        out["properties"] = props
    return out


def run(cfg, name, params):
    level = (params.get("log_level") or "INFO").upper()
    log = mi.setup_logging(KIND, name, level)
    checkpoint_dir = cfg.get("checkpoint_dir") or store.state_root(SCHEME)
    lock = mi.RunLock(store.lock_path(SCHEME, name, checkpoint_dir))
    if not lock.acquire():
        log.info("run skipped: the previous run of this input is still going")
        return 0
    stop = mi.Stopper()
    t0 = time.time()
    out = mi.EventStream()
    stats = {"written": 0, "duplicates": 0, "excluded": 0}
    state_file = store.state_path(SCHEME, name, checkpoint_dir)
    state = mi.load_json(state_file, {})
    client = None
    window = ""
    start = None
    seen = None                      # ids sent: saved with the last complete window's end, also after errors
    committed = None                 # the ids as saved with the last complete window
    dirty = False                    # events sent since the checkpoint was last saved
    account_name = params.get("account", "")
    try:
        account = store.Accounts(store.Splunkd(cfg["session_key"])).get(account_name)
        client = store.client_for(account, log=log, should_stop=stop)
        host = account_name
        page_size = store.number(params, KIND, "page_size")
        delay = store.number(params, KIND, "delay_minutes") * 60
        overlap = store.number(params, KIND, "overlap_minutes") * 60
        excluded = set(store.comma_list(params.get("exclude_event_types")))

        now = int(time.time())
        target = now - delay
        end = api.parse_utc(state.get("end") or "")
        # ids already sent (also after a first run that Splunk stopped part-way)
        seen = {k: v for k, v in (state.get("seen") or {}).items() if isinstance(v, (int, float))}
        committed = dict(seen)
        first_start = api.parse_utc(state.get("start") or "") if end is None else None
        if first_start is not None:
            # a first run that did not complete a window: start where it started
            start = int(first_start)
            log.info("first run for account %s (%s): continuing from %s, where the previous first run started",
                     account_name, account["api_host"], api.utc_text(start))
        elif end is None:
            hours = store.number(params, KIND, "start_hours_ago")
            start = target - hours * 3600
            log.info("first run for account %s (%s): collecting from %s", account_name, account["api_host"],
                     api.utc_text(start))
        else:
            start = int(end) - overlap
        window = f"{api.utc_text(start)} to {api.utc_text(target)}"
        if start >= target:
            if end is None:                         # start_hours_ago = 0: collect from now on
                mi.save_json(state_file, {"end": api.utc_text(target), "seen": seen, "account": account_name})
            log.info("run done: written 0, duplicates 0, excluded 0, api calls 0, window %s (nothing new yet), "
                     "behind %.1f min, %.1f s", window, (now - (end or target)) / 60.0, time.time() - t0)
            return 0

        chunk_start = start
        while chunk_start < target and not stop():
            chunk_end = min(chunk_start + MAX_WINDOW, target)
            pages = 0
            for records, page in api.siem_event_pages(client, chunk_start, chunk_end, page_size):
                pages = page
                for record in records:
                    if stop():                      # stop at once: nothing more after splunkd asked to stop
                        break
                    rid = str(record.get("id") or "")
                    created = created_of(record, chunk_end)
                    if rid and rid in seen:
                        stats["duplicates"] += 1
                        continue
                    if record.get("eventType") in excluded:
                        if rid:
                            seen[rid] = created
                            dirty = True
                        stats["excluded"] += 1
                        continue
                    when = api.parse_utc(record.get("eventDateTimeUtc")) or created
                    out.write(shape(record), when, SOURCETYPE, host)
                    if rid:                         # marked as sent only once written
                        seen[rid] = created
                        dirty = True
                    stats["written"] += 1
                out.flush()
                if stop():
                    break
            if stop():
                # Part of this window was sent: the end stays where it was; the ids sent are saved
                # (finally, below), so the next run repeats the window and skips them.
                break
            log.debug("window %s to %s: %d page(s)", api.utc_text(chunk_start), api.utc_text(chunk_end), pages)
            keep_from = chunk_end - SEEN_KEEP
            seen = {k: v for k, v in seen.items() if v >= keep_from}
            state = {"end": api.utc_text(chunk_end), "seen": seen, "account": account_name}
            mi.save_json(state_file, state)
            committed = dict(seen)
            dirty = False
            if chunk_end >= target:
                break
            chunk_start = chunk_end - 1             # 1 s overlap: boundary events are recognised by id

        if stop():
            log.warning("run stopped: stopped by Splunk (input disabled or restarted, or Splunk stopping); "
                        "written %d. The next run continues from %s and skips the events already sent",
                        stats["written"], resume_point(state, start))
            return 0
        end_now = api.parse_utc(state.get("end") or "") or start
        log.info("run done: written %d, duplicates %d, excluded %d, api calls %d, window %s, behind %.1f min, "
                 "%.1f s", stats["written"], stats["duplicates"], stats["excluded"], client.calls, window,
                 (time.time() - end_now) / 60.0, time.time() - t0)
        return 0
    except mi.OutputClosed:
        log.warning("run stopped: Splunk stopped reading this input's events (input disabled or restarted, or "
                    "Splunk stopping); written %d. Events still on their way may not have reached Splunk, so the "
                    "next run repeats the window from %s; some of its events may be indexed twice",
                    stats["written"], resume_point(state, start))
        return 0
    except api.ApiError as exc:
        if str(exc) == "stopped":
            log.warning("run stopped: stopped by Splunk (input disabled or restarted, or Splunk stopping); "
                        "written %d. The next run continues from %s and skips the events already sent",
                        stats["written"], resume_point(state, start))
            return 0
        log.error("run failed: %s (written %d before the error, window %s)", exc, stats["written"], window or "?")
        return 1
    except store.StoreError as exc:
        log.error("run failed: %s", exc)
        return 1
    except Exception as exc:                                       # keep the details in the log
        log.exception("run failed: %s: %s", type(exc).__name__, exc)
        return 1
    finally:
        out.close()                                                # never raises
        if dirty and seen is not None:
            # A window was cut short after events were sent. The end stays at the last complete window.
            # Pipe to splunkd still open (API error, stop): the ids sent are kept, so the next run repeats
            # the window without duplicates. Pipe closed: events on their way may be lost, so only the
            # ids of the last complete window are kept and the next run sends the window again.
            doc = {"end": state.get("end"), "seen": committed if out.closed else seen, "account": account_name}
            if not state.get("end") and start is not None:
                doc["start"] = api.utc_text(start)              # a first run: the next one starts here too
            try:
                mi.save_json(state_file, doc)
            except OSError as exc:
                log.error("could not save the checkpoint %s: %s", state_file, exc)


if __name__ == "__main__":
    mi.main(KIND, "Absolute SIEM events",
            "Absolute Secure Endpoint SIEM events (device, console and alert activity) from the Absolute API.",
            ARGS, run)
