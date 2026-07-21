# Dependency audit — 2026-07-21

## Installed production set

The production lock file was generated in a clean Python 3.13 virtual environment and `pip check` returned `No broken requirements found`.

## Automated advisory audit

`pip-audit 2.10.1` was installed and invoked against `requirements.txt`, but the isolated execution environment could not resolve `pypi.org`. Therefore, no claim of a complete automated vulnerability-database pass is made.

## Manual current advisory spot-check

- `aiohttp==3.14.1` is the fixed version listed for the June/July 2026 aiohttp advisories checked (including PYSEC-2026-237, PYSEC-2026-2107, GHSA-xcgm-r5h9-7989).
- `python-dotenv==1.2.2` is the patched version for CVE-2026-28684 / GHSA-mf9w-mj56-hr94.
- Targeted searches did not surface a matching direct-package advisory for the exact pinned versions of `aiogram`, `tldextract`, or `idna`; this is a spot-check, not a substitute for a successful full audit.

Run this command in a network-enabled CI environment before every release:

```bash
python -m pip_audit -r requirements.lock.txt
```
