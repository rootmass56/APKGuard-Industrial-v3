"""Deterministic conversion from analyzer output into evidence and findings."""

from __future__ import annotations

import hashlib
from typing import Any

from app.schemas.common import EvidenceType, Severity
from app.schemas.evidence import EvidenceLocation, EvidenceRecord, Finding

EVIDENCE_FACTORY_VERSION = "evidence-factory/3.0.0-phase4"


def stable_id(prefix: str, *parts: Any) -> str:
    material = "\x1f".join(str(part or "") for part in parts)
    digest = hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:16].upper()
    return f"{prefix}-{digest}"


def _severity(value: str | None) -> Severity:
    normalized = (value or "INFO").upper()
    return Severity(normalized) if normalized in Severity._value2member_map_ else Severity.INFO


def add_static_inference_labels(behavioral: dict[str, Any]) -> dict[str, Any]:
    for item in behavioral.get("dynamic_behaviors", []):
        item.setdefault("evidence_type", EvidenceType.INFERRED_STATIC.value)
        item.setdefault("confidence", "low_to_medium")
        item.setdefault("observed_at_runtime", False)
        item.setdefault(
            "limitation",
            "This is inferred from static indicators; it is not observed runtime behaviour.",
        )
    for item in behavioral.get("runtime_indicators", []):
        item.setdefault("evidence_type", EvidenceType.STATICALLY_DETECTED.value)
        item.setdefault("observed_at_runtime", False)
    for item in behavioral.get("anti_analysis_techniques", []):
        item.setdefault("evidence_type", EvidenceType.STATICALLY_DETECTED.value)
        item.setdefault("observed_at_runtime", False)
    return behavioral


def build_evidence_and_findings(
    analysis: dict[str, Any],
    behavioral: dict[str, Any],
    virustotal: dict[str, Any],
    threat_intel: dict[str, Any],
    dynamic: dict[str, Any],
    analyzer_version: str,
) -> tuple[list[EvidenceRecord], list[Finding]]:
    evidence: list[EvidenceRecord] = []
    findings: list[Finding] = []

    def add_record(
        *,
        rule_id: str,
        title: str,
        description: str,
        severity: str,
        evidence_type: EvidenceType,
        source: str,
        value: Any = None,
        path: str | None = None,
        class_name: str | None = None,
        method_name: str | None = None,
        confidence: float | None = None,
        limitation: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        evidence_id = stable_id("EVD", rule_id, source, value, class_name, method_name)
        finding_id = stable_id("FND", rule_id, evidence_id)
        record = EvidenceRecord(
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            title=title,
            description=description,
            location=EvidenceLocation(
                source=source,
                path=path,
                class_name=class_name,
                method_name=method_name,
                value=value,
            ),
            analyzer="apkguard-deterministic-evidence",
            analyzer_version=analyzer_version,
            confidence=confidence,
            observed_at_runtime=evidence_type == EvidenceType.OBSERVED_RUNTIME,
            limitations=[limitation] if limitation else [],
            metadata=metadata or {},
        )
        finding = Finding(
            finding_id=finding_id,
            rule_id=rule_id,
            title=title,
            description=description,
            severity=_severity(severity),
            evidence_type=evidence_type,
            source=source,
            value=value,
            evidence_ids=[evidence_id],
            confidence=confidence,
            limitation=limitation,
            analyzer="apkguard-deterministic-evidence",
            analyzer_version=analyzer_version,
            metadata=metadata or {},
        )
        evidence.append(record)
        findings.append(finding)

    for permission in analysis.get("permissions", {}).get("dangerous", []):
        name = permission.get("permission", "")
        add_record(
            rule_id="MANIFEST-DANGEROUS-PERMISSION",
            title=f"Dangerous permission: {name.split('.')[-1] or 'UNKNOWN'}",
            description=permission.get("reason", "Dangerous Android permission requested."),
            severity="HIGH" if int(permission.get("score", 0)) >= 8 else "MEDIUM",
            evidence_type=EvidenceType.STATICALLY_DETECTED,
            source="AndroidManifest.xml",
            path="/manifest/uses-permission",
            value=name,
            confidence=1.0,
            metadata={"category": "permission", "score_weight": permission.get("score", 0)},
        )

    for api in analysis.get("suspicious_apis", [])[:50]:
        api_name = api.get("api") or "Unknown API"
        add_record(
            rule_id="DEX-SUSPICIOUS-API",
            title=f"Suspicious API reference: {api_name}",
            description=api.get("reason", "Suspicious API reference found in DEX code."),
            severity="HIGH" if int(api.get("score", 0)) >= 8 else "MEDIUM",
            evidence_type=EvidenceType.STATICALLY_DETECTED,
            source=api.get("class", "DEX code"),
            class_name=api.get("class"),
            method_name=api_name,
            value=api_name,
            confidence=0.9,
            metadata={"category": "api", "score_weight": api.get("score", 0)},
        )

    obfuscation = analysis.get("obfuscation", {})
    if obfuscation.get("detected"):
        add_record(
            rule_id="DEX-OBFUSCATION-INDICATOR",
            title="Code obfuscation indicators detected",
            description="; ".join(obfuscation.get("indicators", [])) or "Obfuscation indicators detected.",
            severity="MEDIUM",
            evidence_type=EvidenceType.STATICALLY_DETECTED,
            source="DEX class metadata",
            value=obfuscation.get("indicators", []),
            confidence=0.75,
            metadata={"category": "obfuscation", "score_weight": obfuscation.get("score", 0)},
        )

    for url in analysis.get("urls_ips", {}).get("urls", [])[:20]:
        add_record(
            rule_id="IOC-EMBEDDED-URL",
            title="Embedded URL indicator",
            description="A non-whitelisted URL string was extracted from the APK.",
            severity="INFO",
            evidence_type=EvidenceType.STATICALLY_DETECTED,
            source="APK string extraction",
            value=url,
            confidence=0.85,
            metadata={"category": "network_indicator"},
        )

    if virustotal.get("available") and int(virustotal.get("detected", 0)) > 0:
        add_record(
            rule_id="INTEL-VIRUSTOTAL-DETECTION",
            title="Threat-intelligence detections present",
            description=(
                f"VirusTotal reported {virustotal.get('detected')}/{virustotal.get('total')} "
                "malicious or suspicious detections."
            ),
            severity="CRITICAL" if int(virustotal.get("detected", 0)) > 10 else "HIGH",
            evidence_type=EvidenceType.THREAT_INTEL_MATCH,
            source="VirusTotal hash lookup",
            value=virustotal.get("sha256"),
            confidence=0.95,
            metadata={"category": "threat_intel"},
        )

    if threat_intel.get("hash_match"):
        match = threat_intel["hash_match"]
        add_record(
            rule_id="INTEL-MALWAREBAZAAR-HASH-MATCH",
            title="MalwareBazaar hash match",
            description=f"The APK hash matched threat intelligence family '{match.get('family', 'Unknown')}'.",
            severity="CRITICAL",
            evidence_type=EvidenceType.THREAT_INTEL_MATCH,
            source="MalwareBazaar",
            value=match.get("sha256"),
            confidence=1.0,
            metadata={"category": "threat_intel", "family": match.get("family")},
        )

    for phishing_url in threat_intel.get("phishing_urls", [])[:20]:
        add_record(
            rule_id="INTEL-OPENPHISH-URL-MATCH",
            title="Embedded URL matched OpenPhish",
            description="An URL extracted from the APK matched an active OpenPhish indicator.",
            severity="HIGH",
            evidence_type=EvidenceType.THREAT_INTEL_MATCH,
            source="OpenPhish",
            value=phishing_url,
            confidence=0.95,
            metadata={"category": "threat_intel"},
        )

    for inferred in behavioral.get("dynamic_behaviors", [])[:20]:
        limitation = inferred.get("limitation") or (
            "Static capability or API presence does not prove runtime execution or malicious intent."
        )
        add_record(
            rule_id="STATIC-BEHAVIOUR-INFERENCE",
            title=f"Inferred behaviour: {inferred.get('behavior', 'Unknown')}",
            description=inferred.get("description", "Behaviour inferred from static indicators."),
            severity=inferred.get("severity", "MEDIUM"),
            evidence_type=EvidenceType.INFERRED_STATIC,
            source="Static behaviour inference",
            value=inferred.get("basis", []),
            confidence=0.55,
            limitation=limitation,
            metadata={"category": "inference", "basis": inferred.get("basis", [])},
        )

    advanced = analysis.get("advanced_static", {})
    existing_evidence_ids = {item.evidence_id for item in evidence}
    existing_finding_ids = {item.finding_id for item in findings}
    for raw in advanced.get("evidence", []):
        record = EvidenceRecord.model_validate(raw)
        if record.evidence_id not in existing_evidence_ids:
            evidence.append(record)
            existing_evidence_ids.add(record.evidence_id)
    for raw in advanced.get("findings", []):
        finding = Finding.model_validate(raw)
        if finding.finding_id not in existing_finding_ids:
            findings.append(finding)
            existing_finding_ids.add(finding.finding_id)

    if dynamic.get("dynamic_available"):
        for index, event in enumerate(dynamic.get("observed_events", [])):
            add_record(
                rule_id="RUNTIME-OBSERVED-EVENT",
                title=event.get("title") or event.get("api") or f"Observed runtime event {index + 1}",
                description=event.get("description", "Runtime event captured by the isolated sandbox."),
                severity=event.get("severity", event.get("threat_level", "INFO")),
                evidence_type=EvidenceType.OBSERVED_RUNTIME,
                source="Isolated Android sandbox",
                value=event,
                confidence=1.0,
                metadata={
                    "category": "runtime",
                    "observation_id": event.get("observation_id"),
                    "session_id": event.get("session_id"),
                    "event_category": event.get("category"),
                    "evidence_digest": event.get("evidence_digest"),
                },
            )

    return evidence, findings


def build_mitre_mappings(
    analysis: dict[str, Any],
    score_mitre: list[dict[str, Any]],
    evidence: list[EvidenceRecord],
) -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    seen: set[str] = set()

    permission_evidence = {
        str(record.location.value): record.evidence_id
        for record in evidence
        if record.metadata.get("category") == "permission"
    }
    api_evidence = {
        str(record.location.value): record.evidence_id
        for record in evidence
        if record.metadata.get("category") == "api"
    }

    def add(
        technique_id: str,
        name: str,
        tactic: str,
        reason: str,
        evidence_ids: list[str],
    ) -> None:
        if technique_id in seen:
            return
        seen.add(technique_id)
        mappings.append(
            {
                "technique_id": technique_id,
                "name": name,
                "tactic": tactic,
                "evidence_type": EvidenceType.STATICALLY_DETECTED.value,
                "mapping_confidence": "medium",
                "reason": reason,
                "evidence_ids": [item for item in evidence_ids if item],
                "mapping_version": "apkguard-mobile-attack-map/1.0.0",
            }
        )

    permissions = set(analysis.get("permissions", {}).get("all", []))
    api_names = {str(item.get("api", "")) for item in analysis.get("suspicious_apis", [])}

    if {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS"} & permissions:
        ids = [
            permission_evidence.get("android.permission.READ_SMS", ""),
            permission_evidence.get("android.permission.RECEIVE_SMS", ""),
        ]
        add("T1412", "Capture SMS Messages", "Collection", "SMS capability is declared.", ids)
    if "android.permission.READ_CONTACTS" in permissions:
        add(
            "T1432",
            "Access Contact List",
            "Collection",
            "Contacts capability is declared.",
            [permission_evidence.get("android.permission.READ_CONTACTS", "")],
        )
    if {"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"} & permissions:
        add(
            "T1430",
            "Location Tracking",
            "Collection",
            "Location capability is declared.",
            [
                permission_evidence.get("android.permission.ACCESS_FINE_LOCATION", ""),
                permission_evidence.get("android.permission.ACCESS_COARSE_LOCATION", ""),
            ],
        )
    if "DexClassLoader" in api_names:
        add(
            "T1407",
            "Download New Code at Runtime",
            "Defense Evasion",
            "Dynamic class-loading API reference was found.",
            [api_evidence.get("DexClassLoader", "")],
        )
    if "Runtime.exec" in api_names:
        add(
            "T1623",
            "Command and Scripting Interpreter",
            "Execution",
            "Runtime command-execution API reference was found.",
            [api_evidence.get("Runtime.exec", "")],
        )

    for mapped in score_mitre:
        technique_id = mapped.get("id") or mapped.get("technique_id")
        if technique_id:
            add(
                str(technique_id),
                str(mapped.get("name", "Unknown")),
                str(mapped.get("tactic", "Unknown")),
                "Mapped by deterministic scoring rules.",
                [],
            )
    return mappings
