"""Phase 3 advanced static-analysis orchestration and canonical evidence generation."""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from typing import Any

from app.schemas.common import EvidenceType, Severity
from app.schemas.evidence import EvidenceLocation, EvidenceRecord, Finding, StandardMapping
from app.static_analysis.archive import inventory_apk
from app.static_analysis.code import (
    analyze_code_strings,
    analyze_secrets,
    build_call_graph,
    candidate_string_flows,
    identify_sdks,
)
from app.static_analysis.manifest import analyze_manifest
from app.static_analysis.sbom import build_sbom
from app.static_analysis.util import stable_id

log = logging.getLogger("apkguard.static.engine")
ADVANCED_STATIC_ANALYZER_VERSION = "apkguard-advanced-static/3.2.0-phase3"
RULESET_VERSION = "apkguard-static-rules/3.0.0"


def _severity(value: str) -> Severity:
    normalized = value.upper()
    return Severity(normalized) if normalized in Severity._value2member_map_ else Severity.INFO


def _mappings(standards: dict[str, list[str]], rationale: str) -> list[StandardMapping]:
    output: list[StandardMapping] = []
    for framework, values in standards.items():
        framework_name = {"cwe": "CWE", "maswe": "OWASP MASWE", "attack": "MITRE ATT&CK Mobile"}.get(
            framework, framework
        )
        output.extend(
            StandardMapping(framework=framework_name, identifier=value, rationale=rationale) for value in values
        )
    return output


def _record(
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    category: str,
    source: str,
    path: str | None = None,
    value: Any = None,
    confidence: float = 0.8,
    risk_points: int = 0,
    limitation: str | None = None,
    standards: dict[str, list[str]] | None = None,
    remediation: list[str] | None = None,
    evidence_type: EvidenceType = EvidenceType.STATICALLY_DETECTED,
) -> tuple[EvidenceRecord, Finding]:
    evidence_id = stable_id("EVD", rule_id, source, path, value)
    finding_id = stable_id("FND", rule_id, evidence_id)
    metadata = {
        "category": category,
        "risk_points": risk_points,
        "ruleset_version": RULESET_VERSION,
    }
    evidence = EvidenceRecord(
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        title=title,
        description=description,
        location=EvidenceLocation(source=source, path=path, value=value),
        analyzer="apkguard-advanced-static",
        analyzer_version=ADVANCED_STATIC_ANALYZER_VERSION,
        confidence=confidence,
        observed_at_runtime=False,
        limitations=[limitation] if limitation else [],
        metadata=metadata,
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
        standards=_mappings(standards or {}, description),
        confidence=confidence,
        limitation=limitation,
        remediation=remediation or [],
        analyzer="apkguard-advanced-static",
        analyzer_version=ADVANCED_STATIC_ANALYZER_VERSION,
        metadata=metadata,
    )
    return evidence, finding


def _manifest_records(report: dict[str, Any]) -> list[tuple[EvidenceRecord, Finding]]:
    output: list[tuple[EvidenceRecord, Finding]] = []
    application = report.get("application", {})
    app_rules = (
        (
            "MANIFEST-DEBUGGABLE",
            "debuggable",
            "Debuggable application build",
            "HIGH",
            12,
            {"cwe": ["CWE-489"], "maswe": ["MASWE-0067"]},
        ),
        (
            "MANIFEST-BACKUP",
            "allow_backup",
            "Application data backup is allowed",
            "MEDIUM",
            6,
            {"cwe": ["CWE-530"], "maswe": ["MASWE-0004"]},
        ),
        (
            "MANIFEST-CLEARTEXT",
            "uses_cleartext_traffic",
            "Application permits cleartext traffic",
            "HIGH",
            10,
            {"cwe": ["CWE-319"], "maswe": ["MASWE-0050"]},
        ),
        (
            "MANIFEST-TEST-ONLY",
            "test_only",
            "Application is marked testOnly",
            "MEDIUM",
            5,
            {"cwe": ["CWE-489"]},
        ),
    )
    for rule_id, key, title, severity, points, standards in app_rules:
        if application.get(key) is True:
            output.append(
                _record(
                    rule_id=rule_id,
                    title=title,
                    description=f"AndroidManifest.xml sets android:{key} to true.",
                    severity=severity,
                    category="manifest_configuration",
                    source="AndroidManifest.xml",
                    path="/manifest/application",
                    value=True,
                    confidence=1.0,
                    risk_points=points,
                    standards=standards,
                    remediation=[f"Disable {key} in production unless explicitly required."],
                )
            )
    for component in report.get("exported_components", []):
        permission_protected = bool(
            component.get("permission")
            or component.get("read_permission")
            or component.get("write_permission")
        )
        if permission_protected:
            continue
        component_type = component.get("type", "component")
        severity = "HIGH" if component_type in {"service", "receiver", "provider"} else "MEDIUM"
        points = 10 if severity == "HIGH" else 6
        component_maswe = {
            "activity": "MASWE-0119",
            "activity-alias": "MASWE-0119",
            "service": "MASWE-0062",
            "receiver": "MASWE-0063",
            "provider": "MASWE-0064",
        }.get(component_type)
        component_standards = {"cwe": ["CWE-926"]}
        if component_maswe:
            component_standards["maswe"] = [component_maswe]
        output.append(
            _record(
                rule_id="MANIFEST-EXPORTED-UNPROTECTED",
                title=f"Exported {component_type} lacks a manifest permission",
                description="An externally reachable component does not declare a component-level permission.",
                severity=severity,
                category="attack_surface",
                source="AndroidManifest.xml",
                path=f"/manifest/application/{component_type}",
                value=component.get("name"),
                confidence=0.95,
                risk_points=points,
                limitation="Exposure does not prove that the component accepts unsafe inputs or is exploitable.",
                standards=component_standards,
                remediation=["Set android:exported=false or enforce an appropriately protected permission."],
            )
        )
    for deep_link in report.get("deep_links", []):
        scheme = str(deep_link.get("scheme") or "")
        host = deep_link.get("host")
        if scheme in {"http", "https"} and host and deep_link.get("auto_verify") is True:
            continue
        output.append(
            _record(
                rule_id="MANIFEST-DEEP-LINK-UNVERIFIED",
                title="Potentially unverified deep-link handler",
                description="An exported deep-link handler uses a custom or unverified URL association.",
                severity="MEDIUM",
                category="deep_link",
                source="AndroidManifest.xml",
                path="/manifest/application/activity/intent-filter/data",
                value={"scheme": scheme, "host": host, "component": deep_link.get("component")},
                confidence=0.82,
                risk_points=6,
                limitation="Exploitability depends on URI validation and downstream component logic.",
                standards={"cwe": ["CWE-939"], "maswe": ["MASWE-0058"]},
                remediation=["Use verified Android App Links and validate all incoming URI parameters."],
            )
        )
    network = report.get("network_security", {})
    for config in network.get("cleartext_permitted", []):
        output.append(
            _record(
                rule_id="NETSEC-CLEARTEXT-CONFIG",
                title="Network Security Configuration permits cleartext",
                description="A network-security configuration scope explicitly permits cleartext traffic.",
                severity="HIGH",
                category="network_security",
                source=network.get("reference") or "network_security_config.xml",
                value=config,
                confidence=1.0,
                risk_points=10,
                standards={"cwe": ["CWE-319"], "maswe": ["MASWE-0050"]},
                remediation=["Disable cleartext traffic and use authenticated TLS for all sensitive communication."],
            )
        )
    if network.get("user_trust_anchors"):
        output.append(
            _record(
                rule_id="NETSEC-USER-CA",
                title="User-installed certificate authorities are trusted",
                description="The Network Security Configuration includes user trust anchors.",
                severity="MEDIUM",
                category="network_security",
                source=network.get("reference") or "network_security_config.xml",
                value=network.get("user_trust_anchors"),
                confidence=1.0,
                risk_points=7,
                limitation="This may be appropriate for controlled debugging but broadens production trust.",
                standards={"cwe": ["CWE-295"], "maswe": ["MASWE-0052"]},
                remediation=["Remove user trust anchors from production configurations unless explicitly required."],
            )
        )
    return output


def _signing_records(signature: dict[str, Any]) -> list[tuple[EvidenceRecord, Finding]]:
    output = []
    detected = set(signature.get("detected_schemes", []))
    if signature.get("v1_present") and not detected:
        output.append(
            _record(
                rule_id="SIGNING-V1-ONLY",
                title="Only legacy JAR signing was detected",
                description="V1 signature entries exist, but no APK Signing Block v2/v3 identifier was detected.",
                severity="MEDIUM",
                category="signing",
                source="APK signing metadata",
                value=signature.get("v1_signature_entries", []),
                confidence=0.88,
                risk_points=5,
                limitation="Scheme detection is structural and is not cryptographic signature verification.",
                standards={"cwe": ["CWE-347"]},
                remediation=["Sign release APKs with current Android signing schemes and verify them during CI."],
            )
        )
    for certificate in signature.get("certificates", []):
        if certificate.get("expired") or certificate.get("not_yet_valid"):
            output.append(
                _record(
                    rule_id="SIGNING-CERT-VALIDITY",
                    title="Signing certificate validity anomaly",
                    description="A parsed signing certificate is expired or not yet valid.",
                    severity="HIGH",
                    category="signing",
                    source=certificate.get("entry", "META-INF signature"),
                    value={
                        "sha256": certificate.get("sha256"),
                        "not_valid_before": certificate.get("not_valid_before"),
                        "not_valid_after": certificate.get("not_valid_after"),
                    },
                    confidence=0.98,
                    risk_points=10,
                    standards={"cwe": ["CWE-324"]},
                    remediation=["Use a valid release certificate and document planned signing-key rotation."],
                )
            )
    return output


def run_advanced_static_analysis(
    path: str | Path,
    *,
    apk: Any = None,
    dx: Any = None,
    apk_sha256: str = "",
) -> dict[str, Any]:
    apk_path = Path(path)
    try:
        archive = inventory_apk(apk_path)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        return {
            "status": "failed",
            "analyzer": {"name": "apkguard-advanced-static", "version": ADVANCED_STATIC_ANALYZER_VERSION},
            "errors": [f"Archive inventory failed: {type(exc).__name__}"],
            "evidence": [],
            "findings": [],
            "limitations": ["Advanced static analysis could not read the APK archive."],
        }
    manifest = analyze_manifest(apk_path, apk)
    strings_by_entry = archive.get("strings_by_entry", {})
    code = analyze_code_strings(strings_by_entry)
    secrets = analyze_secrets(strings_by_entry)
    sdks = identify_sdks(strings_by_entry)
    call_graph = build_call_graph(dx)
    candidate_flows = candidate_string_flows(strings_by_entry)
    data_flows = call_graph.get("source_sink_paths", []) or candidate_flows
    package_name = manifest.get("package")
    sbom = build_sbom(
        apk_sha256=apk_sha256 or "unknown",
        package_name=package_name,
        filename=apk_path.name,
        sdks=sdks,
        native_libraries=archive.get("native_libraries", []),
    )

    records: list[tuple[EvidenceRecord, Finding]] = []
    records.extend(_manifest_records(manifest))
    records.extend(_signing_records(archive.get("signature", {})))
    for match in code.get("matches", []):
        first = match["matches"][0]
        records.append(
            _record(
                rule_id=match["rule_id"],
                title=match["title"],
                description=match["description"],
                severity=match["severity"],
                category=match["category"],
                source="DEX/resource strings",
                path=first.get("entry"),
                value=[item.get("pattern") for item in match["matches"]],
                confidence=match["confidence"],
                risk_points=match["risk_points"],
                limitation=match["limitation"],
                standards=match["standards"],
                remediation=match["remediation"],
            )
        )
    for secret in secrets.get("findings", []):
        records.append(
            _record(
                rule_id=secret["rule_id"],
                title="Potential embedded secret",
                description="A secret-like value was deterministically matched and redacted in the report.",
                severity=secret["severity"],
                category="secret",
                source="APK string extraction",
                path=secret["entry"],
                value={"redacted": secret["redacted_value"], "sha256": secret["value_sha256"]},
                confidence=secret["confidence"],
                risk_points=12 if secret["severity"] in {"CRITICAL", "HIGH"} else 6,
                limitation=secret["limitation"],
                standards={"cwe": ["CWE-798"], "maswe": ["MASWE-0005"]},
                remediation=["Revoke exposed credentials and use platform-backed secret provisioning."],
            )
        )
    for flow in data_flows[:20]:
        records.append(
            _record(
                rule_id="FLOW-SOURCE-TO-SINK-CANDIDATE",
                title="Sensitive source-to-sink candidate",
                description="Static analysis found a bounded source-to-sink relationship requiring manual validation.",
                severity="MEDIUM",
                category="data_flow",
                source="Static call/string analysis",
                path=flow.get("entry"),
                value=flow,
                confidence=float(flow.get("confidence", 0.5)),
                risk_points=5,
                limitation=flow.get("limitation") or (
                    "The call path is not a full taint proof and does not prove runtime transmission of sensitive data."
                ),
                standards={"cwe": ["CWE-200"]},
                remediation=[
                    "Trace the data path manually and apply minimization, access control, and transport protection."
                ],
                evidence_type=EvidenceType.INFERRED_STATIC,
            )
        )

    evidence = [item[0] for item in records]
    findings = [item[1] for item in records]
    limitations = [
        "Static findings describe APK content and reachable call candidates; they do not prove runtime execution.",
        (
            "APK signing schemes are structurally detected; cryptographic verification should use apksigner "
            "in a controlled worker."
        ),
        (
            "SBOM versions remain unknown unless deterministically recovered, so no version-specific vulnerability "
            "claim is made."
        ),
        *manifest.get("limitations", []),
        *call_graph.get("limitations", []),
    ]
    return {
        "status": "completed",
        "analyzer": {
            "name": "apkguard-advanced-static",
            "version": ADVANCED_STATIC_ANALYZER_VERSION,
            "ruleset_version": RULESET_VERSION,
        },
        "archive": {key: value for key, value in archive.items() if key != "strings_by_entry"},
        "signing": archive.get("signature", {}),
        "manifest": manifest,
        "attack_surface": {
            "exported_components": manifest.get("exported_components", []),
            "deep_links": manifest.get("deep_links", []),
        },
        "network_security": manifest.get("network_security", {}),
        "code_risks": code,
        "secrets": secrets,
        "native_analysis": {"libraries": archive.get("native_libraries", [])},
        "dependency_inventory": sdks,
        "sbom": sbom,
        "call_graph": call_graph,
        "data_flows": data_flows,
        "evidence": [item.model_dump(mode="json") for item in evidence],
        "findings": [item.model_dump(mode="json") for item in findings],
        "metrics": {
            "evidence_count": len(evidence),
            "finding_count": len(findings),
            "exported_component_count": len(manifest.get("exported_components", [])),
            "deep_link_count": len(manifest.get("deep_links", [])),
            "native_library_count": len(archive.get("native_libraries", [])),
            "dependency_count": len(sdks),
            "candidate_flow_count": len(data_flows),
        },
        "limitations": list(dict.fromkeys(limitations)),
    }
