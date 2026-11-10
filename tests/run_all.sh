#!/bin/sh
# Runs every test of TA-absolute-secure-endpoint (no Splunk, no Absolute account needed).
# ui_test.py needs Playwright with Chromium and jQuery at /usr/share/javascript/jquery/jquery.js.
cd "$(dirname "$0")" || exit 1
rc=0
python3 unit_api.py || rc=1
python3 e2e_inputs.py || rc=1
python3 e2e_stop.py || rc=1
python3 rest_test.py || rc=1
python3 ui_test.py "${1:-/tmp/absolute-ui-shots}" || rc=1
python3 ../tools/package.py ../TA-absolute-secure-endpoint ../dist ${FORBID:+--forbid "$FORBID"} || rc=1
exit $rc
