"""Policy-aware external integration adapters."""

from __future__ import annotations

import logging
from typing import Any

import requests

from app.core.config import Settings

log = logging.getLogger("apkguard.integrations")


class VirusTotalHashClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def lookup(self, sha256: str) -> dict[str, Any]:
        base = {
            "sha256": sha256,
            "source": "virustotal",
            "upload_attempted": False,
            "upload_allowed": self.settings.virustotal_upload_enabled,
        }
        if not self.settings.hash_reputation_allowed_by_policy:
            return {
                **base,
                "available": False,
                "status": "disabled_by_privacy_policy",
                "reason": f"Privacy mode '{self.settings.privacy_mode}' does not permit external hash lookup.",
            }
        if not self.settings.vt_api_key:
            return {
                **base,
                "available": False,
                "status": "disabled",
                "reason": "No VT_API_KEY configured.",
            }

        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": self.settings.vt_api_key},
                timeout=12,
            )
            if response.status_code == 200:
                stats = response.json()["data"]["attributes"].get("last_analysis_stats", {})
                detected = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
                return {
                    **base,
                    "available": True,
                    "status": "completed",
                    "detected": detected,
                    "total": sum(int(value) for value in stats.values()),
                    "malicious": int(stats.get("malicious", 0)),
                    "suspicious": int(stats.get("suspicious", 0)),
                    "harmless": int(stats.get("harmless", 0)),
                    "undetected": int(stats.get("undetected", 0)),
                }
            if response.status_code == 404:
                return {
                    **base,
                    "available": True,
                    "status": "not_found_hash_only",
                    "detected": 0,
                    "total": 0,
                    "not_found": True,
                    "reason": "Hash not found. The APK was not uploaded.",
                }
            log.warning("VirusTotal returned HTTP %s", response.status_code)
            return {
                **base,
                "available": False,
                "status": "error",
                "reason": "VirusTotal lookup failed.",
            }
        except (requests.RequestException, KeyError, TypeError, ValueError) as exc:
            log.warning("VirusTotal hash lookup failed: %s", exc)
            return {
                **base,
                "available": False,
                "status": "error",
                "reason": "VirusTotal lookup failed.",
            }
