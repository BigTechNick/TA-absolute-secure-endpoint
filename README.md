# Absolute Secure Endpoint SIEM Events and Inventory Add-on

Splunk add-on `TA-absolute-secure-endpoint`, version 1.0.2.

Collects Absolute Secure Endpoint SIEM events (device, console and alert activity) and device inventory from the Absolute API, with CIM mappings (Authentication, Change, Alerts, Data Access, Inventory). Accounts, inputs and status are managed in Splunk Web. Not affiliated with Absolute Software.

Splunkbase: https://splunkbase.splunk.com/app/10148

## Layout

- `TA-absolute-secure-endpoint/`: the app exactly as shipped to Splunkbase (unpacked from the release package)
- `tools/package.py`: builds the Splunkbase package and runs offline AppInspect-style checks
- `tools/make_icons.py`: draws the app icons in `static/`
- `tests/`: tests with synthetic data (no Splunk or vendor account needed)
- `docs/`: Splunkbase listing text and screenshots

## Build

```
python3 tools/package.py TA-absolute-secure-endpoint dist --vendor absolute
```

Good: `RESULT: OK`. Then AppInspect:

```
splunk-appinspect inspect dist/TA-absolute-secure-endpoint-<version>.tgz --mode precert --included-tags cloud
```

## Tests

```
sh tests/run_all.sh
```

## Releases

Each version is tagged `v<version>`. Its GitHub release has the exact package uploaded to
Splunkbase attached, with its md5.

## License

Apache-2.0. Independent project, not affiliated with or endorsed by Absolute Software.
