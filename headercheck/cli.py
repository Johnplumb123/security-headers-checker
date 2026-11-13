"""Command-line entry point.

Usage:
    python -m headercheck example.com
    python -m headercheck example.com github.com --json report.json
    python -m headercheck --file urls.txt --markdown report.md
"""
from __future__ import annotations

import argparse
import json
import sys

import requests

from .analysis import (
    Finding, analyse_cert_days, analyse_cookies, analyse_headers, grade, score,
)
from .fetch import cert_days_remaining, fetch_headers, normalise_url

COLOURS = {"pass": "\033[32m", "fail": "\033[31m", "grade": "\033[1;36m", "end": "\033[0m"}


def scan(url: str) -> dict:
    url = normalise_url(url)
    try:
        headers, cookies, final_url = fetch_headers(url)
    except requests.RequestException as exc:
        return {"url": url, "error": str(exc)}

    findings = analyse_headers(headers) + analyse_cookies(cookies)
    findings.append(analyse_cert_days(cert_days_remaining(final_url)))
    if not final_url.startswith("https://"):
        findings.append(Finding("HTTPS redirect", False, "high",
                                f"Site ended up on plain HTTP: {final_url}"))
    pts = score(findings)
    return {
        "url": url,
        "final_url": final_url,
        "score": pts,
        "grade": grade(pts),
        "findings": [f.to_dict() for f in findings],
    }


def print_report(result: dict, colour: bool = True) -> None:
    c = COLOURS if colour else {k: "" for k in COLOURS}
    print(f"\n{result['url']}")
    if "error" in result:
        print(f"  {c['fail']}ERROR{c['end']} {result['error']}")
        return
    print(f"  Grade: {c['grade']}{result['grade']}{c['end']}  ({result['score']}/100)")
    for f in result["findings"]:
        mark = f"{c['pass']}PASS{c['end']}" if f["passed"] else f"{c['fail']}FAIL{c['end']}"
        sev = "" if f["passed"] else f" [{f['severity']}]"
        print(f"  {mark} {f['check']}{sev}: {f['detail']}")


def to_markdown(results: list[dict]) -> str:
    lines = ["# Security headers report", "", "| Site | Grade | Score | Failed checks |",
             "|---|---|---|---|"]
    for r in results:
        if "error" in r:
            lines.append(f"| {r['url']} | - | - | Error: {r['error']} |")
            continue
        failed = [f["check"] for f in r["findings"] if not f["passed"]]
        lines.append(f"| {r['url']} | {r['grade']} | {r['score']} | {', '.join(failed) or 'None'} |")
    for r in results:
        if "error" in r:
            continue
        lines += ["", f"## {r['url']}", ""]
        for f in r["findings"]:
            status = "✅" if f["passed"] else f"❌ ({f['severity']})"
            lines.append(f"- {status} **{f['check']}**: {f['detail']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Grade a website's HTTP security headers and TLS.")
    p.add_argument("urls", nargs="*", help="One or more URLs or domains")
    p.add_argument("--file", help="Text file with one URL per line")
    p.add_argument("--json", metavar="PATH", help="Write the full results as JSON")
    p.add_argument("--markdown", metavar="PATH", help="Write a Markdown report")
    p.add_argument("--no-colour", action="store_true", help="Disable coloured output")
    args = p.parse_args(argv)

    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            urls += [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    if not urls:
        p.error("give at least one URL or --file")

    results = [scan(u) for u in urls]
    for r in results:
        print_report(r, colour=not args.no_colour and sys.stdout.isatty())

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
