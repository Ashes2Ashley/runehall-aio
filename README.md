# Runehall Max AIO Red Ops — Staging Pentest Suite (v8)

Authorized, staging-only DAST / business-logic harness for **your own** Runehall crypto casino SPA.

> **Hard rule:** this toolkit is pinned to `https://staging.runehall.com`. The domain guard exits if `runehall.com` is missing from `TARGET_URL`, production hostnames (`runehall.com`, `www.`, `app.`) are refused, and any `*.runehall.com` host that does not contain `staging` is refused. Do not retarget it at third-party sites or production.

## Files

| File | Purpose |
|------|---------|
| `max_aio_v8.py` | **Current** full AIO Python harness (v8.0) — run this |
| `max_aio_v7.py` | Previous harness (kept for reference) |
| `max_aio_v6.py` | Earlier harness (kept for reference) |
| `max_aio_v5.py` | Earlier harness (kept for reference) |
| `live_inspector_v2.js` | Tampermonkey live inspector (`@match` staging only) |
| `.github/workflows/aio-scan.yml` | GitHub Actions — manual/safe-mode staging scan |

## Safety flags

| Flag | Default | Meaning |
|------|---------|---------|
| `AUTHORIZED` / `AIO_AUTHORIZED` | `True` | Must stay true. Paired with the domain guard. |
| `TARGET_URL` / `AIO_TARGET_URL` | `https://staging.runehall.com` | Hard-pinned. Non-staging `*.runehall.com` hosts are refused. |
| `RUN_STATEFUL` / `AIO_RUN_STATEFUL` | `False` | When `False`, bet/withdraw race, amount probes, JWT forgery attempts, and stateful bonus/free-spin claims **do not fire**. Flip only for intentional mutating tests on disposable staging accounts. |
| Domain guard | always on | Exits if `"runehall.com" not in TARGET_URL`, host looks like production, or host is non-staging `*.runehall.com`. |

Nothing in this suite exfiltrates data, scrapes third parties, or persists credentials off-box. Reports are written locally as HTML + JSON + SARIF + Markdown, plus CI exports (JUnit XML + DefectDojo/Burp + PR-comment Markdown). **Outcome prediction from seeds is intentionally not implemented.**

## What's new in v8

- **New active-safe + recon modules** (staging-only; mutating paths self-gate on `RUN_STATEFUL`):
  - **Access-control matrix** — every discovered API path requested as unauth / user A / user B across `GET/POST/PUT/PATCH/DELETE/OPTIONS`; flags unauth-200-on-authed-route (HIGH), byte-identical A==B responses (IDOR, HIGH), and unauthenticated mutating success (CRITICAL).
  - **Path / encoding auth bypass** — `/admin` baseline then `//admin`, `/admin/..;/`, `%2e` variants, `/actuator`, `/.git/config`, `/.env`, swagger/openapi, etc.; 200-not-login variants flagged (`_looks_like_login` filter).
  - **CSRF posture** — cross-origin `Origin` + no token accepted (HIGH, stateful), missing form token (MEDIUM), and CORS-CSRF chain where ACAO reflects the attacker origin with `ACAC=true` (CRITICAL).
  - **Mass assignment** — injects `role/isAdmin/isPaid/balance/kycStatus/permissions/...`; privileged field echoed back ⇒ CRITICAL (mutating verbs gated behind `RUN_STATEFUL`).
  - **Host-header injection** — `Host/X-Forwarded-Host/Forwarded/...` payloads across `/ , /login, /forgot-password, /reset-password, /api/auth/reset`; flags reflection in body or `Location` (cache-poisoning / reset-link hijack).
  - **Subdomain takeover** — fingerprint map over subfinder-discovered subdomains; service fingerprint match ⇒ CRITICAL.
  - **DOM-XSS** — Playwright init-script hooks `innerHTML/outerHTML/document.write/eval/Function/setTimeout/setInterval` and records `window.__xss`; reflected params routed through the **authenticated** page; HIGH only when a sink actually fires.
  - **HTTP parameter pollution** (`test_hpp`) — duplicate/array params (`role/admin/id/price/amount/discount/coupon/...`); HIGH when the evil value is honored (value-changing + mutating variants gated behind `RUN_STATEFUL`).
  - **Injection** (`test_injection`) — SSTI (`7*7`→49), XXE (`file:///etc/passwd` / OOB), command injection (`;id`), NoSQL operator and LDAP metacharacter probes across `q/search/id/user/.../cmd/url/file/path`; blind OOB variants skip unless `AIO_OOB_HOST` is set.
  - **GraphQL deep attacks** (`test_graphql_deep`) — introspection, field-suggestion leak, query batching, depth abuse across `/graphql,/api/graphql,/v1/graphql,/query`; the destructive aliased `deleteUser` batch is gated behind `RUN_STATEFUL`.
  - **SSRF** (`test_ssrf_real`) — injects loopback/redis/SSH, cloud metadata (`169.254.169.254`, `metadata.google.internal`), int/hex/IPv6 encodings, and `file://gopher://dict://` as app values across SSRF sink params; **only runs when `AIO_OOB_HOST` is configured**; CRITICAL on reflected internal signatures. The harness never fetches metadata itself. (The older heuristic `test_ssrf_param_candidates` is retained.)
  - **JWT advanced** (`test_jwt_advanced`) — offline HS256 dictionary crack (`hmac.compare_digest`, no network), plus `kid` path-traversal/SQLi and `jku` remote-injection forgery against `/api/me,/api/wallet/balance,/api/user` — forgery attempts gated behind `RUN_STATEFUL`. (The older `test_auth_jwt_forgery` is retained.)
  - **Casino race v2** (`test_casino_race_v2`) — `threading.Barrier(n)` + per-thread `requests.Session` + lock-guarded results; CRITICAL double-spend when >1 concurrent POST succeeds. Gated behind `RUN_STATEFUL` + configured endpoint/JWT; preferred over the older `test_casino_race`.
- **Authenticated Playwright contexts** — `_authed_context()` injects the `Authorization` header **and** an auth cookie (name configurable via `AIO_AUTH_COOKIE_NAME`, default `access_token`) scoped to the target host; A / B / unauth contexts.
- **`--retest <finding_id>`** — re-runs the single check behind a prior finding (direct HTTP replay from the stored `replay` descriptor **and** a re-run of the owning phase), reporting `STILL-PRESENT` / `NOT-REPRODUCED` / `LIKELY-FIXED`.
- **History diff** — each run is persisted to `AIO_HISTORY_FILE` (default `max_aio_v8_history.json`, last 20 runs); findings are tagged **new / existing / baseline** and a **fixed-since-last-run** list is produced.
- **More CI output formats** — alongside HTML/JSON/SARIF/MD: **JUnit XML**, a **DefectDojo generic-import JSON** + **Burp-style issues XML**, and a compact **PR-comment Markdown** summary (with the new/existing/fixed delta).
- **Network harness** — optional **HTTP/2** (via `httpx`, `AIO_HTTP2`), **connection-reuse tuning** (`AIO_POOL_CONNECTIONS` / `AIO_POOL_MAXSIZE`), and **request signing** — HMAC (`AIO_SIGN_MODE=hmac`, `AIO_SIGN_SECRET`, `AIO_SIGN_HEADER`, `AIO_SIGN_ALGO`, optional key-id) or static API key (`AIO_SIGN_MODE=apikey`, `AIO_APIKEY_HEADER`, `AIO_APIKEY_VALUE`) applied to every outgoing request.

### New / changed env vars (v8)

| Env var | Purpose |
|---------|---------|
| `AIO_AUTH_COOKIE_NAME` | Auth cookie name injected into Playwright contexts (default `access_token`) |
| `AIO_HTTP2` | `true` to use the HTTP/2 (httpx) transport when available |
| `AIO_POOL_CONNECTIONS` / `AIO_POOL_MAXSIZE` | Connection-reuse tuning (`0` ⇒ derive from concurrency) |
| `AIO_SIGN_MODE` | `hmac` or `apikey` (empty = off) |
| `AIO_SIGN_SECRET` / `AIO_SIGN_HEADER` / `AIO_SIGN_ALGO` / `AIO_SIGN_KEY_ID` / `AIO_SIGN_KEY_ID_HEADER` | HMAC signing config |
| `AIO_APIKEY_HEADER` / `AIO_APIKEY_VALUE` | Static API-key header config |
| `AIO_ENABLE_HISTORY` / `AIO_HISTORY_FILE` | Run-history persistence for new/fixed diffing |
| `AIO_OOB_HOST` | Out-of-band collaborator host enabling blind SSRF / XXE / jku forgery probes (empty = those variants skip) |

```bash
# Verify a single prior finding still reproduces
python3 max_aio_v8.py --retest 537faca4270a0c1e

# HTTP/2 + HMAC-signed requests, don't touch history
AIO_HTTP2=true AIO_SIGN_MODE=hmac AIO_SIGN_SECRET=... python3 max_aio_v8.py --no-history --phases recon
```

Outputs now also include:
`max_aio_v8_report.junit.xml`, `max_aio_v8_report.defectdojo.json`, `max_aio_v8_report.burp.xml`, `max_aio_v8_report.pr-comment.md`.

## What's new in v7

- **Phase orchestration** — ordered runner: `recon → passive → active_safe → stateful`, with per-phase timing, graceful skip when tools/credentials are missing, and `--phases` / `AIO_PHASES` selectors.
- **Bounded concurrency + rate limiting** — polite to staging (`AIO_MAX_CONCURRENCY`, `AIO_RATE_LIMIT_RPS`) with retries/backoff on transient HTTP errors.
- **Consolidated casino business-logic module** — Kodak bonus/rollover (50M GP @ 40x, no max-bet), free-spin/scatter (6+ = 20x + 25 spins, 10-spin retrigger), and provably-fair (detection-only) produce clear **PASS / FAIL / INCONCLUSIVE** verdicts plus a business-logic severity rollup.
- **Reporting upgrade** — self-contained HTML (severity filter buttons, collapsible sections, scorecard, remediation column, OWASP/CWE tags), machine-readable JSON, **SARIF 2.1.0** (GitHub code-scanning), and a Markdown executive summary.
- **Engineering** — `AIOConfig` dataclass, structured logging, input validation, clear exit codes (`0` ok, `10` CRITICAL/HIGH present, `2` config, `3` auth refuse, `1` runtime).

## Phases

| Phase | What runs | Needs |
|-------|-----------|-------|
| `recon` | Security headers, subfinder (optional), rate-limit probe, TRACE/OPTIONS, cookie flags, session fixation | Network to staging |
| `passive` | Playwright SPA crawl + JS secret scan + casino payout/bonus/scatter/provably-fair (read-only) | Playwright (unless skipped) |
| `active_safe` | Reflected XSS *candidates*, SSRF param heuristics (no callbacks), OAuth redirect probes, BOLA/IDOR (needs 2 JWTs), open redirects, nuclei (optional) | Intercepted routes / optional JWTs |
| `stateful` | Casino race, amount validation, JWT forgery attempts, optional ZAP | `RUN_STATEFUL=True` + JWT + endpoints |
| `all` | All of the above (stateful still no-ops unless `RUN_STATEFUL=True`) | — |

```bash
# Subset examples
python3 max_aio_v7.py --phases recon,passive
AIO_PHASES=active_safe python3 max_aio_v7.py
```

## Config — file defaults + env overrides (CI-friendly)

Env wins over file defaults. Never commit real JWTs.

| Env var | Purpose |
|---------|---------|
| `AIO_TARGET_URL` | Target URL (domain guard still forces staging) |
| `AIO_AUTHORIZED` | `true`/`false` |
| `AIO_RUN_STATEFUL` | `true`/`false` (CI workflow forces `false`) |
| `AIO_USER_A_JWT` / `AIO_USER_B_JWT` | Staging test JWTs |
| `AIO_BET_ENDPOINT` | e.g. `/api/games/dice/bet` |
| `AIO_WITHDRAW_ENDPOINT` | e.g. `/api/wallet/withdraw` |
| `AIO_BALANCE_ENDPOINT` | e.g. `/api/wallet/balance` (read-only) |
| `AIO_BONUS_ENDPOINT` | e.g. `/api/bonus/status` (read-only accounting) |
| `AIO_FREESPIN_ENDPOINT` | e.g. `/api/games/slots/spins` |
| `AIO_SEED_ENDPOINT` | e.g. `/api/fairness/seeds` |
| `AIO_AUTH_TEST_ENDPOINT` | Authenticated staging route for gated JWT forgery attempts |
| `AIO_SKIP_PLAYWRIGHT` | Skip browser crawl |
| `AIO_ENABLE_ZAP` | Opt-in ZAP docker scan (off by default) |
| `AIO_PHASES` | Comma-separated phase list |
| `AIO_MAX_CONCURRENCY` | Default `6` |
| `AIO_RATE_LIMIT_RPS` | Default `4` (be polite to staging) |
| `AIO_REQUEST_TIMEOUT` | Default `10` |
| `AIO_MAX_RETRIES` | Default `3` (backoff on 429/5xx) |
| `AIO_OUTPUT_PREFIX` | Default `max_aio_v7_report` |
| `AIO_LOG_LEVEL` | Default `INFO` |

- BOLA/IDOR **no-ops** until both JWTs are real staging tokens.
- Casino race + amount + JWT forgery + stateful bonus/free-spin claims **no-op** until `RUN_STATEFUL=True`, a JWT is set (where required), and the relevant endpoint path is filled.
- Read-only modules (payout integrity, bonus accounting compare, scatter policy compare, seed leak detection, cookie flags, session fixation heuristics, OAuth redirect probes) run without `RUN_STATEFUL`.

## Modules (all versions retained)

### Inherited from v4 / v5 / v6
- JWT structure analysis (alg=none, long-lived, elevated claims, jku/x5u)
- Security header audit (HSTS, CSP, XFO, nosniff, Referrer-Policy)
- Open redirect checks on intercepted redirect-ish params
- JS bundle secret scan (AWS / Google / Stripe / Firebase / private keys)
- Subfinder OSINT (optional)
- Rate-limit probe (20 rapid GETs)
- Playwright SPA crawl: storage exposure, `/admin` route bypass, CORS, prototype pollution, postMessage, WebSocket auth, GraphQL introspection, API endpoint inventory
- Dual-JWT BOLA/IDOR
- Nuclei + optional ZAP
- Casino payout/odds integrity (read-only), bet/withdraw race (`RUN_STATEFUL`), amount validation (`RUN_STATEFUL`)
- Reflected-param XSS *candidates*, SSRF param heuristics (no callbacks), HTTP method tampering (TRACE/OPTIONS)
- Bonus / rollover accounting vs Kodak policy; free-spin / scatter rules; provably-fair seed detection (no prediction)
- JWT forgery attempts (`RUN_STATEFUL`), session fixation, cookie flags, OAuth `redirect_uri` probes

### New in v7
- Phase runner with selectors + timing + skip reasons
- Rate-limited HTTP session with retries
- Casino module PASS/FAIL/INCONCLUSIVE verdicts + business-logic rollup
- HTML severity filtering / scorecard / OWASP+CWE tags / remediation column
- SARIF export + Markdown executive summary
- Exit codes for CI gating

## Install

```bash
# Required
python3 -m pip install requests playwright
python3 -m playwright install chromium

# Optional (enrichment)
# - nuclei:   https://github.com/projectdiscovery/nuclei
# - subfinder: https://github.com/projectdiscovery/subfinder
# - docker + ZAP image (opt-in via AIO_ENABLE_ZAP=true)
```

## Run (local)

```bash
cd /path/to/runehall-aio
export AIO_USER_A_JWT="..."
export AIO_USER_B_JWT="..."
export AIO_BALANCE_ENDPOINT="/api/wallet/balance"
export AIO_RUN_STATEFUL=false
python3 max_aio_v7.py
# or a subset:
python3 max_aio_v7.py --phases recon,passive
```

Outputs (cwd), prefix configurable via `AIO_OUTPUT_PREFIX`:

- `max_aio_v7_report.html` — interactive HTML
- `max_aio_v7_report.json` — full machine-readable report
- `max_aio_v7_report.sarif` — SARIF 2.1.0 for GitHub code scanning
- `max_aio_v7_report.md` — Markdown executive summary

Optional later pass with stateful probes (staging test accounts only):

```bash
export AIO_RUN_STATEFUL=true
export AIO_BET_ENDPOINT="/api/games/dice/bet"
export AIO_AUTH_TEST_ENDPOINT="/api/wallet/balance"
python3 max_aio_v7.py --phases all
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed; no CRITICAL/HIGH |
| `10` | Completed; CRITICAL or HIGH present (useful CI gate) |
| `2` | Config / phase validation error |
| `3` | Authorization / domain-guard refuse |
| `1` | Unhandled runtime error |

## Run (GitHub Actions)

1. In the repo: **Settings → Secrets and variables → Actions**, add any of:
   `AIO_USER_A_JWT`, `AIO_USER_B_JWT`, `AIO_BET_ENDPOINT`, `AIO_WITHDRAW_ENDPOINT`,
   `AIO_BALANCE_ENDPOINT`, `AIO_BONUS_ENDPOINT`, `AIO_FREESPIN_ENDPOINT`,
   `AIO_SEED_ENDPOINT`, `AIO_AUTH_TEST_ENDPOINT`.
2. **Actions → aio-scan-staging → Run workflow** (optional: choose phases / skip Playwright).
3. Download the `max-aio-v7-report` artifact (HTML/JSON/SARIF/MD). SARIF is also uploaded via `github/codeql-action/upload-sarif` when permissions allow.

The workflow **will not** enable `RUN_STATEFUL`. For stateful probes, run locally against staging with disposable accounts.

## Live inspector (browser)

Install Tampermonkey, add `live_inspector_v2.js`. It only matches `*://staging.runehall.com/*`. It hooks `fetch` / `WebSocket`, dumps storage, and can fuzz visible inputs — the XSS button auto-submits forms, so use it carefully on staging.

## Scope reminder

This is **your** staging app. Do not retarget, do not run against production player data, and keep `RUN_STATEFUL=False` unless you are deliberately exercising mutating endpoints on disposable staging accounts. Bonus/rollover and free-spin modules verify **server-side enforcement** of your own documented rules; they are not instructions to abuse live balances.
