"""Pure analysis functions: no network access, so they are easy to unit test."""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict

# Severity -> points deducted from a starting score of 100
PENALTY = {"high": 20, "medium": 10, "low": 5, "info": 0}


@dataclass
class Finding:
    check: str
    passed: bool
    severity: str  # high | medium | low | info
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


def _lower_keys(headers: dict) -> dict:
    return {k.lower(): v for k, v in headers.items()}


def analyse_headers(headers: dict) -> list[Finding]:
    """Check the response headers for common security controls."""
    h = _lower_keys(headers)
    findings: list[Finding] = []

    # HSTS
    hsts = h.get("strict-transport-security")
    if not hsts:
        findings.append(Finding("Strict-Transport-Security", False, "high",
                                "Missing. Browsers may be downgraded to plain HTTP."))
    else:
        m = re.search(r"max-age=(\d+)", hsts)
        max_age = int(m.group(1)) if m else 0
        if max_age < 15552000:  # 180 days
            findings.append(Finding("Strict-Transport-Security", False, "low",
                                    f"max-age={max_age} is below the recommended 180 days."))
        else:
            findings.append(Finding("Strict-Transport-Security", True, "info", hsts))

    # CSP
    csp = h.get("content-security-policy")
    if not csp:
        findings.append(Finding("Content-Security-Policy", False, "high",
                                "Missing. No browser-side defence against XSS/injection."))
    elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
        findings.append(Finding("Content-Security-Policy", False, "medium",
                                "Present but allows 'unsafe-inline' or 'unsafe-eval'."))
    else:
        findings.append(Finding("Content-Security-Policy", True, "info", "Present."))

    # Clickjacking: X-Frame-Options OR CSP frame-ancestors
    xfo = h.get("x-frame-options")
    if xfo or (csp and "frame-ancestors" in csp):
        findings.append(Finding("Clickjacking protection", True, "info",
                                xfo or "CSP frame-ancestors"))
    else:
        findings.append(Finding("Clickjacking protection", False, "medium",
                                "No X-Frame-Options or CSP frame-ancestors."))

    # MIME sniffing
    if h.get("x-content-type-options", "").lower() == "nosniff":
        findings.append(Finding("X-Content-Type-Options", True, "info", "nosniff"))
    else:
        findings.append(Finding("X-Content-Type-Options", False, "low",
                                "Missing or not set to 'nosniff'."))

    # Referrer policy
    if h.get("referrer-policy"):
        findings.append(Finding("Referrer-Policy", True, "info", h["referrer-policy"]))
    else:
        findings.append(Finding("Referrer-Policy", False, "low",
                                "Missing. Full URLs may leak to third parties."))

    # Permissions policy
    if h.get("permissions-policy"):
        findings.append(Finding("Permissions-Policy", True, "info", "Present."))
    else:
        findings.append(Finding("Permissions-Policy", False, "low",
                                "Missing. Camera/mic/geolocation access not restricted."))

    # Information disclosure
    for header in ("server", "x-powered-by", "x-aspnet-version"):
        value = h.get(header, "")
        if value and re.search(r"\d", value):
            findings.append(Finding(f"Info disclosure ({header})", False, "low",
                                    f"Reveals software version: {value}"))

    return findings


def analyse_cookies(set_cookie_headers: list[str]) -> list[Finding]:
    """Check each Set-Cookie header for Secure, HttpOnly and SameSite flags."""
    findings: list[Finding] = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip()
        attrs = [a.strip().lower() for a in raw.split(";")[1:]]
        missing = []
        if "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if not any(a.startswith("samesite") for a in attrs):
            missing.append("SameSite")
        if missing:
            findings.append(Finding(f"Cookie '{name}'", False, "medium",
                                    "Missing flags: " + ", ".join(missing)))
        else:
            findings.append(Finding(f"Cookie '{name}'", True, "info", "All flags set."))
    return findings


def analyse_cert_days(days_left: int | None) -> Finding:
    if days_left is None:
        return Finding("TLS certificate", False, "high", "Could not retrieve certificate.")
    if days_left < 0:
        return Finding("TLS certificate", False, "high", f"Expired {-days_left} days ago.")
    if days_left < 14:
        return Finding("TLS certificate", False, "medium", f"Expires in {days_left} days.")
    return Finding("TLS certificate", True, "info", f"Valid for {days_left} more days.")


def score(findings: list[Finding]) -> int:
    total = 100 - sum(PENALTY[f.severity] for f in findings if not f.passed)
    return max(total, 0)


def grade(points: int) -> str:
    for threshold, letter in ((90, "A"), (75, "B"), (60, "C"), (45, "D"), (30, "E")):
        if points >= threshold:
            return letter
    return "F"
