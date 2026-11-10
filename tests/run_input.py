"""
run_input.py <script> [args] - runs one of the add-on's modular input scripts against
fake_absolute: same code, with the API's base URL and CA pointed at the test server
(FAKE_ABSOLUTE_URL, FAKE_ABSOLUTE_CA) and the fake 'splunk' package on the path.
"""
import os
import runpy
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP_BIN = os.path.join(os.path.dirname(HERE), "TA-absolute-secure-endpoint", "bin")
sys.path[:0] = [os.path.join(HERE, "fake_splunk"), APP_BIN]
import absolute_se_api as api  # noqa: E402
if os.environ.get("FAULT_AFTER"):
    import faulthandler
    faulthandler.dump_traceback_later(int(os.environ["FAULT_AFTER"]), exit=True)

URL, CA = os.environ["FAKE_ABSOLUTE_URL"], os.environ["FAKE_ABSOLUTE_CA"]
_ctx = api.ssl_context


def make_ssl_context(self):
    ctx = _ctx()
    ctx.load_verify_locations(CA)
    return ctx


api.Client.base_url = lambda self: URL
api.Client.make_ssl_context = make_ssl_context
script = sys.argv[1]
sys.argv = [script] + sys.argv[2:]
runpy.run_path(script, run_name="__main__")
