"""Code-string rules, secret controls, SDK inventory, call graph, and candidate flows."""

from __future__ import annotations

import math
import re
from collections import defaultdict, deque
from typing import Any

from app.static_analysis.rules import CODE_RULES, SINK_PATTERNS, SOURCE_PATTERNS
from app.static_analysis.util import redact, sha256_bytes

SECRET_RULES = (
    ("PRIVATE-KEY", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "CRITICAL", 0.99),
    ("AWS-ACCESS-KEY", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "HIGH", 0.96),
    ("GOOGLE-API-KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "HIGH", 0.94),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "MEDIUM", 0.82),
    (
        "GENERIC-TOKEN",
        re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"']?([A-Za-z0-9_./+=-]{16,})"),
        "MEDIUM",
        0.62,
    ),
)
PLACEHOLDER_TERMS = ("example", "dummy", "sample", "changeme", "your_api", "placeholder", "test_key")
SDK_RULES = {
    "OkHttp": ("okhttp3", "pkg:maven/com.squareup.okhttp3/okhttp"),
    "Retrofit": ("retrofit2", "pkg:maven/com.squareup.retrofit2/retrofit"),
    "Firebase": ("com/google/firebase", "pkg:maven/com.google.firebase/firebase-core"),
    "Facebook SDK": ("com/facebook", "pkg:maven/com.facebook.android/facebook-core"),
    "Adjust": ("com/adjust/sdk", "pkg:maven/com.adjust.sdk/adjust-android"),
    "AppsFlyer": ("com/appsflyer", "pkg:maven/com.appsflyer/af-android-sdk"),
    "Branch": ("io/branch", "pkg:maven/io.branch.sdk.android/library"),
    "Crashlytics": ("com/crashlytics", "pkg:maven/com.crashlytics.sdk.android/crashlytics"),
    "Volley": ("com/android/volley", "pkg:maven/com.android.volley/volley"),
    "Cordova": ("org/apache/cordova", "pkg:maven/org.apache.cordova/framework"),
}


def _combined_strings(strings_by_entry: dict[str, list[str]]) -> list[tuple[str, str]]:
    return [(entry, value) for entry, values in strings_by_entry.items() for value in values]


def analyze_code_strings(strings_by_entry: dict[str, list[str]]) -> dict[str, Any]:
    corpus = _combined_strings(strings_by_entry)
    matches: list[dict[str, Any]] = []
    for rule in CODE_RULES:
        matched: list[dict[str, Any]] = []
        lowered_patterns = tuple(pattern.lower() for pattern in rule.patterns)
        for entry, value in corpus:
            lower = value.lower()
            for pattern, lowered in zip(rule.patterns, lowered_patterns, strict=True):
                if lowered in lower:
                    matched.append({"entry": entry, "pattern": pattern, "value": value[:240]})
                    break
            if len(matched) >= 12:
                break
        # Multi-pattern correlation rules require every configured pattern; single rules require one.
        if len(rule.patterns) > 1 and rule.rule_id in {"TLS-SSL-ERROR-PROCEED", "WEBVIEW-JS-INTERFACE"}:
            observed_patterns = {item["pattern"] for item in matched}
            if not all(pattern in observed_patterns for pattern in rule.patterns):
                continue
        if not matched:
            continue
        matches.append(
            {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "description": rule.description,
                "severity": rule.severity,
                "category": rule.category,
                "confidence": rule.confidence,
                "risk_points": rule.risk_points,
                "matches": matched,
                "standards": {
                    "cwe": list(rule.cwe),
                    "maswe": list(rule.maswe),
                    "attack": list(rule.attack),
                },
                "remediation": list(rule.remediation),
                "limitation": "String or reference presence does not prove runtime reachability or malicious intent.",
            }
        )
    return {"matches": matches, "rule_count": len(CODE_RULES)}


def analyze_secrets(strings_by_entry: dict[str, list[str]]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for entry, value in _combined_strings(strings_by_entry):
        if any(term in value.lower() for term in PLACEHOLDER_TERMS):
            continue
        for rule_id, pattern, severity, confidence in SECRET_RULES:
            match = pattern.search(value)
            if not match:
                continue
            secret = match.group(1) if match.lastindex else match.group(0)
            findings.append(
                {
                    "rule_id": f"SECRET-{rule_id}",
                    "entry": entry,
                    "severity": severity,
                    "confidence": confidence,
                    "redacted_value": redact(secret),
                    "value_sha256": sha256_bytes(secret.encode("utf-8", errors="ignore")),
                    "length": len(secret),
                    "limitation": "The report intentionally redacts secret material; verify context before rotation.",
                }
            )
            break
        if len(findings) >= 50:
            break
    return {"findings": findings, "redaction_applied": True}


def identify_sdks(strings_by_entry: dict[str, list[str]]) -> list[dict[str, Any]]:
    corpus = "\n".join(value for _, value in _combined_strings(strings_by_entry)).lower()
    output = []
    for name, (needle, purl) in SDK_RULES.items():
        if needle.lower() in corpus:
            output.append(
                {
                    "name": name,
                    "purl": purl,
                    "version": None,
                    "version_status": "not_determined",
                    "confidence": 0.85,
                    "evidence": needle,
                }
            )
    return output


def _method_identity(method: Any) -> str:
    raw_method = getattr(method, "method", method)
    class_name = str(
        getattr(raw_method, "class_name", "")
        or getattr(raw_method, "get_class_name", lambda: "")()
    )
    name = str(getattr(raw_method, "name", "") or getattr(raw_method, "get_name", lambda: "")())
    descriptor = str(
        getattr(raw_method, "descriptor", "")
        or getattr(raw_method, "get_descriptor", lambda: "")()
    )
    return f"{class_name}->{name}{descriptor}"


def build_call_graph(dx: Any, *, max_nodes: int = 5000, max_edges: int = 20000) -> dict[str, Any]:
    if dx is None:
        return {
            "available": False,
            "nodes": 0,
            "edges": 0,
            "source_sink_paths": [],
            "limitations": ["Androguard analysis graph was unavailable."],
        }
    graph: dict[str, set[str]] = defaultdict(set)
    node_objects: dict[str, Any] = {}
    try:
        for analysis_class in dx.get_classes():
            for method_analysis in analysis_class.get_methods():
                method = getattr(method_analysis, "method", method_analysis)
                source = _method_identity(method)
                if not source or len(node_objects) >= max_nodes:
                    continue
                node_objects[source] = method
                try:
                    xrefs = method_analysis.get_xref_to()
                except (AttributeError, TypeError, ValueError):
                    continue
                for _, target, _ in xrefs:
                    if sum(len(values) for values in graph.values()) >= max_edges:
                        break
                    graph[source].add(_method_identity(target))
    except (AttributeError, TypeError, ValueError) as exc:
        return {
            "available": False,
            "nodes": len(node_objects),
            "edges": sum(len(values) for values in graph.values()),
            "source_sink_paths": [],
            "limitations": [f"Call-graph extraction was partial: {type(exc).__name__}"],
        }
    paths = _find_source_sink_paths(graph)
    return {
        "available": True,
        "nodes": len(set(graph) | {target for values in graph.values() for target in values}),
        "edges": sum(len(values) for values in graph.values()),
        "source_sink_paths": paths,
        "limitations": [
            (
                "Paths represent bounded call reachability, not proof that a particular value is tainted from "
                "source to sink."
            ),
            "Reflection, native code, callbacks, and framework dispatch may be absent from the graph.",
        ],
    }


def _labels(identity: str, catalogue: dict[str, tuple[str, ...]]) -> list[str]:
    lower = identity.lower()
    return [
        label
        for label, patterns in catalogue.items()
        if any(pattern.lower() in lower for pattern in patterns)
    ]


def _find_source_sink_paths(
    graph: dict[str, set[str]],
    *,
    max_depth: int = 6,
    max_paths: int = 40,
) -> list[dict[str, Any]]:
    sources = {node: _labels(node, SOURCE_PATTERNS) for node in graph}
    sources = {node: labels for node, labels in sources.items() if labels}
    output: list[dict[str, Any]] = []
    for source, source_labels in sources.items():
        queue = deque([(source, [source])])
        visited = {source}
        while queue and len(output) < max_paths:
            current, path = queue.popleft()
            sink_labels = _labels(current, SINK_PATTERNS) if current != source else []
            if sink_labels:
                output.append(
                    {
                        "source_categories": source_labels,
                        "sink_categories": sink_labels,
                        "path": path,
                        "depth": len(path) - 1,
                        "confidence": 0.62,
                        "evidence_type": "INFERRED_STATIC",
                    }
                )
                continue
            if len(path) > max_depth:
                continue
            for target in sorted(graph.get(current, set())):
                if target not in visited:
                    visited.add(target)
                    queue.append((target, [*path, target]))
    return output


def candidate_string_flows(strings_by_entry: dict[str, list[str]]) -> list[dict[str, Any]]:
    output = []
    for entry, values in strings_by_entry.items():
        joined = "\n".join(values).lower()
        source_labels = [
            label
            for label, patterns in SOURCE_PATTERNS.items()
            if any(pattern.lower() in joined for pattern in patterns)
        ]
        sink_labels = [
            label
            for label, patterns in SINK_PATTERNS.items()
            if any(pattern.lower() in joined for pattern in patterns)
        ]
        if source_labels and sink_labels:
            output.append(
                {
                    "entry": entry,
                    "source_categories": source_labels,
                    "sink_categories": sink_labels,
                    "confidence": 0.35,
                    "evidence_type": "INFERRED_STATIC",
                    "limitation": (
                        "Source and sink indicators co-occur in one archive entry; no call or data-flow path "
                        "is proven."
                    ),
                }
            )
    return output[:40]


def entropy(value: str) -> float:
    if not value:
        return 0.0
    probabilities = [value.count(char) / len(value) for char in set(value)]
    return -sum(probability * math.log2(probability) for probability in probabilities)
