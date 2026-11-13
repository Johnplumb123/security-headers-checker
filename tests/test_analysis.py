from headercheck.analysis import (
    analyse_cert_days, analyse_cookies, analyse_headers, grade, score,
)
from headercheck.cli import to_markdown

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
}


def failed(findings):
    return {f.check for f in findings if not f.passed}


def test_well_configured_site_gets_an_a():
    findings = analyse_headers(GOOD_HEADERS)
    assert failed(findings) == set()
    assert grade(score(findings)) == "A"


def test_empty_headers_fail_everything():
    findings = analyse_headers({})
    assert "Strict-Transport-Security" in failed(findings)
    assert "Content-Security-Policy" in failed(findings)
    assert "Clickjacking protection" in failed(findings)
    assert grade(score(findings)) in {"E", "F"}


def test_header_names_are_case_insensitive():
    lower = {k.lower(): v for k, v in GOOD_HEADERS.items()}
    assert failed(analyse_headers(lower)) == set()


def test_short_hsts_max_age_is_flagged():
    headers = {**GOOD_HEADERS, "Strict-Transport-Security": "max-age=300"}
    assert "Strict-Transport-Security" in failed(analyse_headers(headers))


def test_unsafe_inline_csp_is_flagged():
    headers = {**GOOD_HEADERS,
               "Content-Security-Policy": "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'"}
    assert "Content-Security-Policy" in failed(analyse_headers(headers))


def test_x_frame_options_satisfies_clickjacking_check():
    headers = {"X-Frame-Options": "DENY"}
    assert "Clickjacking protection" not in failed(analyse_headers(headers))


def test_server_version_disclosure():
    headers = {**GOOD_HEADERS, "Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"}
    flagged = failed(analyse_headers(headers))
    assert "Info disclosure (server)" in flagged
    assert "Info disclosure (x-powered-by)" in flagged


def test_server_header_without_version_is_fine():
    headers = {**GOOD_HEADERS, "Server": "cloudflare"}
    assert failed(analyse_headers(headers)) == set()


def test_cookie_flags():
    findings = analyse_cookies([
        "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
        "tracker=xyz; Path=/",
    ])
    assert failed(findings) == {"Cookie 'tracker'"}
    bad = next(f for f in findings if not f.passed)
    assert "Secure" in bad.detail and "HttpOnly" in bad.detail and "SameSite" in bad.detail


def test_cert_expiry_checks():
    assert analyse_cert_days(200).passed
    assert not analyse_cert_days(5).passed
    assert analyse_cert_days(-3).severity == "high"
    assert analyse_cert_days(None).severity == "high"


def test_grade_boundaries():
    assert grade(100) == "A"
    assert grade(90) == "A"
    assert grade(89) == "B"
    assert grade(0) == "F"
    assert score([]) == 100


def test_markdown_report():
    result = {"url": "https://example.com", "score": 80, "grade": "B",
              "findings": [f.to_dict() for f in analyse_headers({**GOOD_HEADERS, "Referrer-Policy": ""})]}
    md = to_markdown([result, {"url": "https://down.test", "error": "timeout"}])
    assert "| https://example.com | B | 80 | Referrer-Policy |" in md
    assert "Error: timeout" in md
