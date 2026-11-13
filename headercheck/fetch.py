"""Network code: fetch headers and TLS certificate details."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

USER_AGENT = "headercheck/1.0 (+https://github.com/)"


def normalise_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def fetch_headers(url: str, timeout: float = 10.0) -> tuple[dict, list[str], str]:
    """Return (headers, set_cookie_headers, final_url)."""
    resp = requests.get(url, timeout=timeout, allow_redirects=True,
                        headers={"User-Agent": USER_AGENT})
    cookies = resp.raw.headers.getlist("Set-Cookie") if resp.raw else []
    return dict(resp.headers), list(cookies), resp.url


def cert_days_remaining(url: str, timeout: float = 10.0) -> int | None:
    """Days until the TLS certificate expires, or None if it can't be fetched."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    host, port = parsed.hostname, parsed.port or 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError):
        return None
    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    expires = expires.replace(tzinfo=timezone.utc)
    return (expires - datetime.now(timezone.utc)).days
