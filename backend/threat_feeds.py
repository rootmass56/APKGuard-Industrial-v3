"""
APKGuard AI — threat_feeds.py

Threat-intelligence enrichment for APK hashes and embedded URLs.

Sprint 0 principles:
- External lookup failures are reported as unavailable, never as clean.
- URLhaus remains disabled until an authenticated, validated integration is added.
- MalwareBazaar hash lookups and OpenPhish URL checks are best-effort enrichment.
- The legacy ``malwarebazaar`` feed key is retained for frontend compatibility,
  although the recent Android feed currently comes from AlienVault OTX.
"""

from __future__ import annotations

import json
import logging
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

log = logging.getLogger("apkguard.threat_feeds")

CACHE_FILE = Path(tempfile.gettempdir()) / "apkguard_threat_cache.json"
CACHE_TTL_SECONDS = 3600
REQUEST_TIMEOUT_SECONDS = 15

USER_AGENT = "APKGuard-AI-Research/2.1"
FORM_HEADERS = {
    "User-Agent": USER_AGENT,
    "Content-Type": "application/x-www-form-urlencoded",
}
JSON_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json",
}


def _utc_now_iso() -> str:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _load_cache() -> dict[str, Any] | None:
    """Load a fresh threat-feed cache entry, or return ``None``."""
    try:
        if not CACHE_FILE.exists():
            return None

        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            log.warning("Ignoring malformed threat-feed cache: expected object")
            return None

        cached_at = data.get("cache_timestamp")
        if not isinstance(cached_at, (int, float)):
            return None

        if time.time() - cached_at < CACHE_TTL_SECONDS:
            return data

    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        log.warning("Unable to read the threat-feed cache: %s", exc)

    return None


def _save_cache(data: dict[str, Any]) -> None:
    """Persist threat-feed data without interrupting a scan on cache failure."""
    cache_data = dict(data)
    cache_data["cache_timestamp"] = time.time()

    try:
        CACHE_FILE.write_text(
            json.dumps(cache_data, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as exc:
        log.warning("Unable to write the threat-feed cache: %s", exc)


def fetch_otx_android_iocs(limit: int = 10) -> list[dict[str, Any]]:
    """Fetch recent Android-malware pulse metadata from AlienVault OTX."""
    safe_limit = max(0, min(int(limit), 100))
    if safe_limit == 0:
        return []

    try:
        response = requests.get(
            "https://otx.alienvault.com/otxapi/pulses/",
            params={"limit": 20, "q": "android malware"},
            headers=JSON_HEADERS,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()

        pulses = payload.get("results", [])
        if not isinstance(pulses, list):
            log.warning("OTX returned an unexpected response structure")
            return []

        results: list[dict[str, Any]] = []
        for pulse in pulses[:safe_limit]:
            if not isinstance(pulse, dict):
                continue

            pulse_name = str(pulse.get("name") or "Unknown Android threat")
            tags = pulse.get("tags")
            if not isinstance(tags, list):
                tags = []

            results.append(
                {
                    "sha256": "",
                    "filename": pulse_name,
                    "family": pulse_name,
                    "tags": [str(tag) for tag in tags],
                    "first_seen": str(pulse.get("created") or ""),
                    "source": "AlienVault OTX",
                    "pulse_id": str(pulse.get("id") or ""),
                    "evidence_type": "THREAT_INTEL_METADATA",
                }
            )

        return results

    except (requests.RequestException, ValueError, TypeError) as exc:
        log.warning("AlienVault OTX lookup failed: %s", exc)
        return []


def fetch_malwarebazaar_recent(limit: int = 10) -> list[dict[str, Any]]:
    """
    Return recent Android-malware metadata for the legacy dashboard feed.

    The current recent-sample metadata source is AlienVault OTX. The historical
    function name is retained temporarily to avoid breaking the Sprint 0 API.
    """
    return fetch_otx_android_iocs(limit)


def check_hash_malwarebazaar(sha256: str) -> dict[str, Any]:
    """Check a SHA-256 hash against MalwareBazaar without uploading the APK."""
    normalized_hash = str(sha256 or "").strip().lower()
    if len(normalized_hash) != 64 or any(
        character not in "0123456789abcdef" for character in normalized_hash
    ):
        return {
            "found": False,
            "status": "invalid_hash",
            "source": "MalwareBazaar",
        }

    try:
        response = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": normalized_hash},
            headers=FORM_HEADERS,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
        query_status = str(payload.get("query_status") or "unknown")

        if query_status == "ok":
            samples = payload.get("data")
            if not isinstance(samples, list) or not samples:
                return {
                    "found": False,
                    "status": "malformed_response",
                    "source": "MalwareBazaar",
                }

            sample = samples[0]
            if not isinstance(sample, dict):
                return {
                    "found": False,
                    "status": "malformed_response",
                    "source": "MalwareBazaar",
                }

            tags = sample.get("tags")
            if not isinstance(tags, list):
                tags = []

            return {
                "found": True,
                "status": "match",
                "family": str(sample.get("signature") or "Unknown"),
                "tags": [str(tag) for tag in tags],
                "first_seen": str(sample.get("first_seen") or ""),
                "reporter": str(sample.get("reporter") or ""),
                "source": "MalwareBazaar",
                "sha256": normalized_hash,
                "evidence_type": "THREAT_INTEL_MATCH",
            }

        if query_status in {"hash_not_found", "no_results"}:
            return {
                "found": False,
                "status": "not_found",
                "source": "MalwareBazaar",
            }

        return {
            "found": False,
            "status": "unavailable",
            "reason": query_status,
            "source": "MalwareBazaar",
        }

    except requests.RequestException as exc:
        log.warning("MalwareBazaar hash lookup failed: %s", exc)
        return {
            "found": False,
            "status": "unavailable",
            "reason": "request_failed",
            "source": "MalwareBazaar",
        }
    except (ValueError, TypeError) as exc:
        log.warning("MalwareBazaar returned invalid data: %s", exc)
        return {
            "found": False,
            "status": "unavailable",
            "reason": "invalid_response",
            "source": "MalwareBazaar",
        }


def fetch_openphish_urls(limit: int = 50) -> list[str]:
    """Fetch active phishing URLs from the OpenPhish community feed."""
    safe_limit = max(0, min(int(limit), 5000))
    if safe_limit == 0:
        return []

    try:
        response = requests.get(
            "https://openphish.com/feed.txt",
            timeout=REQUEST_TIMEOUT_SECONDS,
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()
        urls = [line.strip() for line in response.text.splitlines() if line.strip()]
        return urls[:safe_limit]

    except requests.RequestException as exc:
        log.warning("OpenPhish feed lookup failed: %s", exc)
        return []


def _normalize_url_for_comparison(url: str) -> str:
    """Normalize only superficial URL differences used during feed matching."""
    return str(url or "").strip().lower().rstrip("/")


def check_url_openphish(url: str, phish_list: list[str]) -> bool:
    """Return ``True`` when a URL matches an OpenPhish indicator."""
    target = _normalize_url_for_comparison(url)
    if not target:
        return False

    for indicator in phish_list:
        candidate = _normalize_url_for_comparison(indicator)
        if not candidate:
            continue

        if target == candidate:
            return True

        if target.startswith(f"{candidate}/") or candidate.startswith(f"{target}/"):
            return True

    return False


def check_domain_openphish(domain: str, phish_list: list[str]) -> list[str]:
    """Return OpenPhish indicators containing an exact normalized hostname."""
    from urllib.parse import urlparse

    normalized_domain = str(domain or "").strip().lower().rstrip(".")
    if not normalized_domain:
        return []

    matches: list[str] = []
    for indicator in phish_list:
        try:
            hostname = (urlparse(indicator).hostname or "").lower().rstrip(".")
        except ValueError:
            continue

        if hostname == normalized_domain:
            matches.append(indicator)

    return matches


def fetch_urlhaus_recent(limit: int = 10) -> list[dict[str, Any]]:
    """
    Return recent URLhaus indicators.

    Sprint 0 intentionally disables this integration until authenticated access,
    response validation, caching, and test coverage are implemented. An empty
    list means unavailable, not safe or clean.
    """
    del limit
    return []


def get_threat_feeds(force_refresh: bool = False) -> dict[str, Any]:
    """Return combined threat-intelligence feeds with best-effort caching."""
    if not force_refresh:
        cached = _load_cache()
        if cached is not None:
            return cached

    log.info("Refreshing APKGuard threat-intelligence feeds")

    recent_android = fetch_malwarebazaar_recent(10)
    openphish_urls = fetch_openphish_urls(100)
    urlhaus_urls = fetch_urlhaus_recent(10)

    feeds: dict[str, Any] = {
        # Legacy field retained for compatibility with the current frontend.
        "malwarebazaar": recent_android,
        "recent_android_source": "AlienVault OTX",
        "urlhaus": urlhaus_urls,
        "urlhaus_status": "disabled",
        "openphish": openphish_urls,
        "openphish_status": "available" if openphish_urls else "unavailable",
        "last_updated": _utc_now_iso(),
        "status": "ok" if recent_android or openphish_urls else "unavailable",
    }

    _save_cache(feeds)
    return feeds


def scan_apk_against_feeds(
    sha256: str,
    urls_in_apk: list[str] | None = None,
) -> dict[str, Any]:
    """Cross-reference an APK hash and embedded URLs against configured feeds."""
    embedded_urls = urls_in_apk or []
    result: dict[str, Any] = {
        "available": True,
        "status": "completed",
        "hash_match": None,
        "hash_lookup_status": "not_run",
        "phishing_urls": [],
        "openphish_status": "not_run",
        "threat_level": "unknown",
        "intel_source": [],
    }

    hash_result = check_hash_malwarebazaar(sha256)
    result["hash_lookup_status"] = hash_result.get("status", "unknown")

    if hash_result.get("found"):
        result["hash_match"] = hash_result
        result["threat_level"] = "malicious"
        result["intel_source"].append("MalwareBazaar")

    if embedded_urls:
        feeds = get_threat_feeds()
        phish_list = feeds.get("openphish", [])
        result["openphish_status"] = feeds.get("openphish_status", "unknown")

        if isinstance(phish_list, list):
            for url in embedded_urls:
                if check_url_openphish(str(url), phish_list):
                    result["phishing_urls"].append(str(url))

        if result["phishing_urls"]:
            result["intel_source"].append("OpenPhish")
            if result["threat_level"] != "malicious":
                result["threat_level"] = "suspicious"
    else:
        result["openphish_status"] = "not_applicable"

    if (
        result["threat_level"] == "unknown"
        and result["hash_lookup_status"] == "not_found"
        and result["openphish_status"] in {"available", "not_applicable"}
    ):
        result["threat_level"] = "no_known_match"

    result["intel_source"] = sorted(set(result["intel_source"]))
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("=== APKGuard Threat Feeds Test ===\n")
    print("[1] Fetching recent Android threat metadata...")
    for sample in fetch_malwarebazaar_recent(5):
        print(f"  {sample['filename']:40} {sample['family']}")

    print("\n[2] Fetching OpenPhish URLs...")
    for phishing_url in fetch_openphish_urls(5):
        print(f"  {phishing_url}")

    print("\n[Done]")
