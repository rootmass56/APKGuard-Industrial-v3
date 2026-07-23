"""
APKGuard AI — url_scanner.py

WhatsApp/SMS URL triage with local heuristics and optional OpenPhish
reputation enrichment.

Security notes:
- Redirect resolution is limited to known URL shorteners.
- Each redirect target is checked to block private, loopback, link-local,
  reserved, multicast, and unspecified IP addresses.
- A failed reputation lookup is reported as unavailable, never as clean.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

log = logging.getLogger("apkguard.url_scanner")

USER_AGENT = "APKGuard-AI-Research/2.1"
REQUEST_TIMEOUT = (5, 10)
OPENPHISH_CACHE_TTL_SECONDS = 600
MAX_REDIRECTS = 5

SUSPICIOUS_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\d{1,3}(?:-\d{1,3}){3}", "IP-style value used in the hostname"),
    (
        r"(?:free|winner|won|prize|claim|urgent|verify|suspend|block|limited)",
        "Urgency or prize-related language",
    ),
    (
        r"(?:paypal|amazon|google|apple|microsoft|bank|boi|sbi|hdfc|icici)"
        r".+\.(?:tk|ml|ga|cf|gq|xyz|top|click|link)(?:/|$)",
        "Brand impersonation combined with a suspicious TLD",
    ),
    (
        r"(?:login|signin|verify|update|confirm|secure|account)"
        r".+\.(?:tk|ml|ga|cf|gq|xyz)(?:/|$)",
        "Fake login-page pattern",
    ),
    (r"https?://[^/]*\d{5,}", "Suspicious long numeric hostname component"),
)

SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".xyz",
        ".top",
        ".click",
        ".link",
        ".work",
        ".loan",
    }
)

SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "rb.gy",
        "cutt.ly",
        "short.io",
        "tiny.cc",
        "is.gd",
        "buff.ly",
    }
)

_OPENPHISH_CACHE: set[str] = set()
_OPENPHISH_CACHE_TIME = 0.0


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def extract_urls(text: str) -> list[str]:
    """Extract HTTP(S) URLs from a message and trim common punctuation."""
    pattern = r"https?://[^\s<>\"{}|\\^`\[\]]+"
    matches = re.findall(pattern, str(text or ""), flags=re.IGNORECASE)
    return [match.rstrip(".,;:!?)]}'\"") for match in matches]


def _normalized_hostname(url: str) -> str:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    return hostname


def _is_known_shortener(hostname: str) -> bool:
    return any(
        hostname == shortener or hostname.endswith(f".{shortener}")
        for shortener in SHORTENERS
    )


def _is_public_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _validate_public_http_url(url: str) -> None:
    """Raise ``ValueError`` when a URL is unsafe for server-side retrieval."""
    parsed = urlparse(url)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed")

    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        raise ValueError("URL does not contain a valid hostname")

    try:
        direct_ip = ipaddress.ip_address(hostname)
    except ValueError:
        direct_ip = None

    if direct_ip is not None:
        if not _is_public_ip(str(direct_ip)):
            raise ValueError("Private or reserved IP destinations are blocked")
        return

    try:
        address_info = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError("Hostname could not be resolved") from exc

    resolved_addresses = {entry[4][0] for entry in address_info}
    if not resolved_addresses:
        raise ValueError("Hostname did not resolve to an IP address")

    if any(not _is_public_ip(address) for address in resolved_addresses):
        raise ValueError("Hostname resolves to a private or reserved address")


def _request_without_environment_proxy(
    method: str,
    url: str,
) -> requests.Response:
    """Issue a minimal request while ignoring environment proxy variables."""
    session = requests.Session()
    session.trust_env = False

    try:
        return session.request(
            method=method,
            url=url,
            allow_redirects=False,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            stream=True,
        )
    finally:
        session.close()


def unshorten_url(url: str) -> tuple[str, bool]:
    """Resolve a known short URL through a bounded, validated redirect chain."""
    try:
        hostname = _normalized_hostname(url)
    except ValueError as exc:
        log.warning("Unable to parse URL %s: %s", url, exc)
        return url, False

    if not _is_known_shortener(hostname):
        return url, False

    current_url = url

    for _ in range(MAX_REDIRECTS):
        try:
            _validate_public_http_url(current_url)
            response = _request_without_environment_proxy("HEAD", current_url)
        except (ValueError, requests.RequestException) as exc:
            log.warning("Unable to resolve shortened URL %s: %s", current_url, exc)
            return current_url, True

        try:
            if not 300 <= response.status_code < 400:
                return current_url, True

            location = response.headers.get("Location")
            if not location:
                return current_url, True

            next_url = urljoin(current_url, location)
            _validate_public_http_url(next_url)

            if next_url == current_url:
                return current_url, True

            current_url = next_url
        except ValueError as exc:
            log.warning("Blocked unsafe redirect from %s: %s", current_url, exc)
            return current_url, True
        finally:
            response.close()

    log.warning("Redirect limit reached while resolving %s", url)
    return current_url, True


def _normalize_openphish_url(url: str) -> str:
    return str(url or "").strip().lower().rstrip("/")


def _load_openphish_feed() -> tuple[set[str], str]:
    """Return cached OpenPhish indicators and lookup status."""
    global _OPENPHISH_CACHE_TIME

    if (
        _OPENPHISH_CACHE
        and time.time() - _OPENPHISH_CACHE_TIME < OPENPHISH_CACHE_TTL_SECONDS
    ):
        return _OPENPHISH_CACHE, "available"

    try:
        response = requests.get(
            "https://openphish.com/feed.txt",
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()

        indicators = {
            _normalize_openphish_url(line)
            for line in response.text.splitlines()
            if line.strip()
        }

        _OPENPHISH_CACHE.clear()
        _OPENPHISH_CACHE.update(indicators)
        _OPENPHISH_CACHE_TIME = time.time()
        return _OPENPHISH_CACHE, "available"

    except requests.RequestException as exc:
        log.warning("OpenPhish lookup failed: %s", exc)
        return set(), "unavailable"


def _check_openphish_with_status(url: str) -> tuple[bool, str]:
    indicators, status = _load_openphish_feed()
    if status != "available":
        return False, status

    normalized = _normalize_openphish_url(url)
    return normalized in indicators, status


def check_openphish(url: str) -> bool:
    """Compatibility wrapper returning only the OpenPhish match result."""
    matched, _status = _check_openphish_with_status(url)
    return matched


def _parse_public_url(url: str) -> tuple[str, str]:
    """Validate URL structure and return normalized hostname and TLD."""
    parsed = urlparse(url)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Unsupported URL scheme")

    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise ValueError("Missing hostname")

    tld = f".{hostname.rsplit('.', 1)[-1]}" if "." in hostname else ""
    return hostname, tld


def analyze_url(url: str) -> dict[str, object]:
    """Analyze a single URL using local indicators and OpenPhish enrichment."""
    original_url = str(url or "").strip()
    result: dict[str, object] = {
        "url": original_url,
        "domain": "",
        "risk_level": "unknown",
        "risk_score": 0,
        "threats": [],
        "in_openphish": False,
        "openphish_status": "not_run",
        "suspicious_patterns": [],
        "tld": "",
        "timestamp": _utc_now_iso(),
        "evidence_type": "URL_TRIAGE",
    }

    if not original_url:
        result["threats"] = ["Empty URL"]
        result["risk_level"] = "invalid"
        result["risk_score"] = 40
        return result

    resolved_url, was_shortened = unshorten_url(original_url)
    result["url"] = resolved_url

    suspicious_patterns = result["suspicious_patterns"]
    if not isinstance(suspicious_patterns, list):
        suspicious_patterns = []
        result["suspicious_patterns"] = suspicious_patterns

    if was_shortened:
        result["original_url"] = original_url
        result["unshortened_to"] = resolved_url

        if resolved_url != original_url:
            suspicious_patterns.append(f"Shortener resolves to: {resolved_url}")
        else:
            suspicious_patterns.append(
                "URL shortener detected; destination could not be verified"
            )
            result["risk_score"] = int(result["risk_score"]) + 10

    try:
        domain, tld = _parse_public_url(resolved_url)
        result["domain"] = domain
        result["tld"] = tld
    except (TypeError, ValueError, AttributeError) as exc:
        log.warning("Invalid URL supplied for analysis: %s", exc)
        result["threats"] = ["Invalid URL format"]
        result["risk_level"] = "invalid"
        result["risk_score"] = 40
        return result

    matched_openphish, openphish_status = _check_openphish_with_status(resolved_url)
    result["openphish_status"] = openphish_status

    threats = result["threats"]
    if not isinstance(threats, list):
        threats = []
        result["threats"] = threats

    if matched_openphish:
        result["in_openphish"] = True
        threats.append("URL matched an OpenPhish indicator")
        result["risk_score"] = int(result["risk_score"]) + 80

    if tld in SUSPICIOUS_TLDS:
        suspicious_patterns.append(f"Suspicious TLD: {tld}")
        result["risk_score"] = int(result["risk_score"]) + 30

    for pattern, description in SUSPICIOUS_PATTERNS:
        if re.search(pattern, resolved_url, re.IGNORECASE):
            suspicious_patterns.append(description)
            result["risk_score"] = int(result["risk_score"]) + 20

    score = min(int(result["risk_score"]), 100)
    result["risk_score"] = score

    if score >= 70 or bool(result["in_openphish"]):
        result["risk_level"] = "malicious"
    elif score >= 30:
        result["risk_level"] = "suspicious"
    elif openphish_status == "unavailable":
        result["risk_level"] = "unknown"
    else:
        result["risk_level"] = "safe"

    result["verdict_basis"] = (
        "Heuristic triage and OpenPhish enrichment; not a guarantee of safety"
    )
    return result


def scan_message(message: str) -> dict[str, object]:
    """Scan a WhatsApp/SMS message for embedded HTTP(S) URLs."""
    urls = extract_urls(message)

    if not urls:
        return {
            "message_scanned": True,
            "urls_found": 0,
            "urls": [],
            "overall_risk": "safe",
            "max_risk_score": 0,
            "summary": "No HTTP(S) URLs were found in the message",
            "timestamp": _utc_now_iso(),
        }

    results = [analyze_url(url) for url in urls]
    scores = [int(result.get("risk_score", 0)) for result in results]
    max_score = max(scores, default=0)

    if any(result.get("risk_level") == "malicious" for result in results):
        overall_risk = "malicious"
    elif any(result.get("risk_level") == "suspicious" for result in results):
        overall_risk = "suspicious"
    elif any(result.get("risk_level") == "unknown" for result in results):
        overall_risk = "unknown"
    else:
        overall_risk = "safe"

    return {
        "message_scanned": True,
        "urls_found": len(urls),
        "urls": results,
        "overall_risk": overall_risk,
        "max_risk_score": max_score,
        "summary": f"Found {len(urls)} URL(s). Risk: {overall_risk.upper()}",
        "timestamp": _utc_now_iso(),
    }
