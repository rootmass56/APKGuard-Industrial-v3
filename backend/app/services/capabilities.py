"""Optional legacy capability discovery isolated from API startup."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable


@dataclass(frozen=True, slots=True)
class LoadedFunction:
    name: str
    function: Callable[..., Any] | None
    available: bool
    reason: str | None = None


def _load(module_name: str, attribute: str) -> LoadedFunction:
    try:
        module = importlib.import_module(module_name)
        function = getattr(module, attribute)
        return LoadedFunction(f"{module_name}.{attribute}", function, True)
    except Exception as exc:
        return LoadedFunction(f"{module_name}.{attribute}", None, False, type(exc).__name__)


@dataclass(frozen=True, slots=True)
class CapabilityRegistry:
    dynamic_analysis: LoadedFunction
    ml_classifier: LoadedFunction
    smali_explanation: LoadedFunction
    threat_feeds: LoadedFunction
    threat_scan: LoadedFunction
    siem_alert: LoadedFunction

    @classmethod
    def discover(cls) -> "CapabilityRegistry":
        return cls(
            dynamic_analysis=_load("dynamic_analyzer", "run_dynamic_analysis"),
            ml_classifier=_load("ml_classifier", "kmeans_classify"),
            smali_explanation=_load("smali_deobfuscator", "run_smali_deobfuscation"),
            threat_feeds=_load("threat_feeds", "get_threat_feeds"),
            threat_scan=_load("threat_feeds", "scan_apk_against_feeds"),
            siem_alert=_load("siem_webhook", "send_siem_alert"),
        )

    def health(self) -> dict[str, Any]:
        return {
            "dynamic_analysis_module": self.dynamic_analysis.available,
            "dynamic_execution_status": "controlled_by_phase4_sandbox_policy",
            "ml_classifier_module": self.ml_classifier.available,
            "smali_module": self.smali_explanation.available,
            "threat_feeds_module": self.threat_feeds.available and self.threat_scan.available,
            "siem_module": self.siem_alert.available,
        }


@lru_cache(maxsize=1)
def get_capabilities() -> CapabilityRegistry:
    return CapabilityRegistry.discover()
