# headercheck

![CI](https://github.com/Johnplumb123/security-headers-checker/actions/workflows/ci.yml/badge.svg)

A Python command-line tool that grades a website's security configuration from the outside: HTTP security headers, cookie flags, TLS certificate expiry, HTTPS redirection and server version disclosure. It gives each site an A–F grade and can export JSON or Markdown reports.

I built it to speed up the first pass of web security reviews: the passive checks you'd normally do by hand in browser dev tools or Burp before deeper testing.

## Example

```
$ python -m headercheck example.com

https://example.com
  Grade: D  (45/100)
  FAIL Strict-Transport-Security [high]: Missing. Browsers may be downgraded to plain HTTP.
  FAIL Content-Security-Policy [high]: Missing. No browser-side defence against XSS/injection.
  FAIL Clickjacking protection [medium]: No X-Frame-Options or CSP frame-ancestors.
  ...
  PASS TLS certificate: Valid for 112 more days.
```

## What it checks

| Check | Why it matters | Severity if missing |
|---|---|---|
| Strict-Transport-Security | Stops SSL-stripping / downgrade to HTTP | High |
| Content-Security-Policy | Limits impact of XSS; flags `unsafe-inline` / `unsafe-eval` | High |
| X-Frame-Options or CSP `frame-ancestors` | Prevents clickjacking | Medium |
| Cookie flags (Secure, HttpOnly, SameSite) | Protects session cookies from theft and CSRF | Medium |
| X-Content-Type-Options | Stops MIME-type sniffing | Low |
| Referrer-Policy | Stops URLs leaking to third parties | Low |
| Permissions-Policy | Restricts camera, mic, geolocation access | Low |
| Server / X-Powered-By versions | Version numbers help attackers find known CVEs | Low |
| TLS certificate expiry | Expired certs break trust and availability | High |
| HTTPS redirect | Site should never end up on plain HTTP | High |

Scoring starts at 100 and deducts 20 / 10 / 5 points for high / medium / low findings.

## Usage

```bash
pip install -r requirements.txt

python -m headercheck example.com
python -m headercheck site1.com site2.com --json results.json
python -m headercheck --file urls.txt --markdown report.md
```

## Project structure

```
headercheck/
  analysis.py   # pure functions: checks, scoring, grading (no network, fully unit tested)
  fetch.py      # network: HTTP request + TLS certificate lookup
  cli.py        # argument parsing and report output
tests/
  test_analysis.py
```

Keeping the analysis separate from the network code means every check can be tested offline with fake headers.

## Running tests

```bash
pip install pytest
pytest -v
```

Tests run automatically on every push through GitHub Actions.

## Limitations and next steps

- Passive checks only: it doesn't test whether a CSP can actually be bypassed.
- Doesn't yet check TLS protocol versions or cipher suites.
- Ideas: CORS misconfiguration checks, `security.txt` detection, HTML dashboard output.

## Legal

Only scan sites you own or have permission to test. This tool sends one normal GET request per site, the same as a browser visit.
