# URL Guard Bot 1.2.1 — security and build audit

Date: 2026-07-21
Scope: uploaded Python sources, packaging, runtime configuration, defensive URL processing, local stress behavior, and release artifact.

## Result

**Release status: ready for controlled deployment after adding a real Telegram bot token.**

No high-severity defect was found in the application source during this review. The package compiles, installs from a wheel, and passes the included test suite and static checks.

## Reproducible checks

| Check | Result |
|---|---:|
| Python `compileall` | PASS |
| Wheel build and clean-venv import | PASS (`url_guard_bot==1.2.1`) |
| pytest | PASS — 121 tests |
| Ruff lint | PASS |
| Ruff format check | PASS |
| Bandit application/script scan | PASS — 0 findings after review of fixed loopback-only subprocess calls |
| `pip check` | PASS |
| Runtime listener check | PASS — analyzer session startup created no new socket FD/listener |
| Secret packaging check | PASS — `.env` is excluded |
| Docker hardening checks | PASS — non-root, read-only FS, dropped capabilities, no-new-privileges, resource limits |

## Security controls verified

- HTTP/HTTPS only; credentials in authority and non-default ports are rejected by default.
- Loopback, private, link-local, shared, multicast, reserved, unspecified, metadata, and IPv4-mapped internal addresses are rejected.
- Every DNS record is validated before `aiohttp` receives it; DNS cache is disabled.
- HTTP and HTML meta-refresh redirects are normalized and checked before following.
- HTTPS downgrade, redirect loops, dangerous redirect targets, and sensitive cross-domain redirects are blocked.
- Cookies, proxy environment variables, and automatic decompression are disabled.
- GET fallback is bounded with `Range` and a maximum read size.
- Local blacklist is checked before the initial request and before redirect requests.
- Rate limiting, global analysis semaphore, request deadlines, per-host connection limit, and bounded user-key storage are enabled.
- Query strings are redacted in user-visible results.
- URLs containing sensitive query keys are not requested over the network by default.
- `tldextract` network updates and filesystem cache are disabled.

## Safe load test

The in-process rate-limiter stress test ran 40,000 checks (5,000 users × 8 requests):

- allowed: 25,000
- blocked: 15,000
- throughput: approximately 33,887 checks/second
- p50 latency: approximately 0.0049 ms
- p95 latency: approximately 0.0083 ms
- peak traced Python memory: approximately 42.9 MB

This is intentionally not a remote DoS/DDoS test. It validates local limiter behavior without attacking any network service.

## Network lab

A loopback-only HTTP lab ran 100 requests against `127.0.0.1`, verified the temporary port with a Python TCP probe, and achieved approximately 815 requests/second in the sandbox. `nmap` and `tcpdump` were not installed in the execution image, so the included lab reports them as unavailable. The project includes a hardcoded-loopback script that can run both tools on an authorized machine; it cannot accept a remote target.

## Dependency audit limitation

`pip-audit` could not resolve `pypi.org` from the isolated environment. A current manual OSV spot-check confirmed that the pinned `aiohttp==3.14.1` and `python-dotenv==1.2.2` are the fixed versions for the reviewed 2026 advisories. Run `pip-audit -r requirements.lock.txt` in network-enabled CI before production deployment.

## Residual risks

1. Any URL checker that contacts arbitrary public URLs can trigger a state-changing endpoint implemented incorrectly with GET/HEAD. Blocking sensitive query keys reduces this risk but cannot eliminate path-only or custom-key actions.
2. The local blacklist is not a replacement for external reputation services or a malware sandbox.
3. The in-memory rate limiter is per process. A multi-replica deployment needs a shared limiter such as Redis at the ingress layer.
4. Application-level SSRF protection should be backed by an egress firewall that denies private, link-local, and cloud metadata networks.
5. The Docker base image tag is not digest-pinned; pin an approved digest in your own CI/CD policy.

## Deployment gate

Before launch:

1. Copy `.env.example` to `.env` and insert a newly created BotFather token.
2. Keep `BLOCK_SENSITIVE_QUERY_REQUESTS=true` and default ports 80/443.
3. Run `python scripts/security_check.py` and `python -m pip_audit -r requirements.lock.txt` in a network-enabled environment.
4. Apply host/container egress filtering for internal and metadata networks.
5. Do not expose an inbound port; the bot uses Telegram long polling.
