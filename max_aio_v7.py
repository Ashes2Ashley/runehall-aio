#!/usr/bin/env python3
"""
Runehall.com - Max AIO Red Ops Pipeline (v7.0)

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
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:  # pragma: no cover
    HAS_PLAYWRIGHT = False

# ---------------------------------------------------------------------------
# Version / exit codes
# ---------------------------------------------------------------------------
VERSION = "7.0"
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
    output_prefix: str = "max_aio_v7_report"
    log_level: str = "INFO"

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
            output_prefix=_env_str("AIO_OUTPUT_PREFIX", "max_aio_v7_report") or "max_aio_v7_report",
            log_level=_env_str("AIO_LOG_LEVEL", "INFO") or "INFO",
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
    logger = logging.getLogger("max_aio_v7")
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


def build_session(cfg: AIOConfig) -> requests.Session:
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
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=cfg.max_concurrency)
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    sess.headers.update({"User-Agent": f"Runehall-MaxAIO/{VERSION} (staging-authorized)"})
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

    # ---- auth helpers ----
    def auth_headers(self, jwt: Optional[str] = None) -> Dict[str, str]:
        token = jwt or self.cfg.user_a_jwt
        if not token or "YOUR_USER" in token:
            return {}
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def jwt_configured(self, which: str = "A") -> bool:
        tok = self.cfg.user_a_jwt if which == "A" else self.cfg.user_b_jwt
        return bool(tok) and "YOUR_USER" not in tok

    # ---- HTTP wrappers (rate-limited + timed) ----
    def http_get(self, url: str, **kwargs: Any) -> requests.Response:
        self.rate_limiter.acquire_sync()
        timeout = kwargs.pop("timeout", self.cfg.request_timeout)
        return self.session.get(url, timeout=timeout, **kwargs)

    def http_post(self, url: str, json_body: Optional[dict] = None, **kwargs: Any) -> requests.Response:
        self.rate_limiter.acquire_sync()
        timeout = kwargs.pop("timeout", self.cfg.request_timeout)
        return self.session.post(url, json=json_body, timeout=timeout, **kwargs)

    def http_request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        self.rate_limiter.acquire_sync()
        timeout = kwargs.pop("timeout", self.cfg.request_timeout)
        return self.session.request(method, url, timeout=timeout, **kwargs)

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
                ]
                self.audit_security_headers()
                self.run_subfinder()
                self.check_rate_limiting()
                self.test_http_method_tampering()
                self.test_auth_cookie_flags()
                self.test_auth_session_fixation()

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
                    "run_nuclei", "test_casino_amount_validation_note",
                ]
                self.test_reflected_xss_candidates()
                self.test_ssrf_param_candidates()
                self.test_auth_oauth_redirect()
                self.test_bola()
                self.test_open_redirect()
                self.run_nuclei()
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
                        "test_casino_race", "test_casino_amount_validation",
                        "test_auth_jwt_forgery", "run_zap",
                    ]
                    self.test_casino_race()
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
        }

        prefix = self.cfg.output_prefix
        json_path = f"{prefix}.json"
        html_path = f"{prefix}.html"
        sarif_path = f"{prefix}.sarif"
        md_path = f"{prefix}.md"

        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        with open(html_path, "w") as f:
            f.write(self._render_html(findings, sev_counts))
        with open(sarif_path, "w") as f:
            json.dump(self._render_sarif(findings), f, indent=2)
        with open(md_path, "w") as f:
            f.write(self._render_markdown(findings, sev_counts))

        self.log.info("Reports: %s | %s | %s | %s", html_path, json_path, sarif_path, md_path)
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

    def _render_sarif(self, findings: List[Tuple[str, Dict[str, Any]]]) -> Dict[str, Any]:
        """SARIF 2.1.0 for GitHub code scanning upload."""
        level_map = {
            "CRITICAL": "error", "HIGH": "error",
            "MEDIUM": "warning", "LOW": "note", "INFO": "note",
        }
        rules = {}
        results = []
        for idx, (cat, f) in enumerate(findings):
            rule_id = f"aio-v7/{cat}"
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
                    "commandLine": "python3 max_aio_v7.py",
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
    p.add_argument("--output-prefix", default=None, help="Report filename prefix (default max_aio_v7_report)")
    return p.parse_args(argv)


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

    # Safety gates BEFORE any network I/O
    try:
        enforce_safety_gates(cfg)
    except SystemExit as e:
        # Preserve explicit refuse messages
        print(str(e) if e.args else "Authorization failed.", file=sys.stderr)
        return EXIT_AUTH_REFUSED

    log = setup_logging(cfg.log_level)
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
