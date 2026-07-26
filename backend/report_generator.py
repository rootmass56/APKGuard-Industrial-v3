"""
APKGuard — report_generator.py

Generates an evidence-oriented PDF report from a completed APKGuard scan result.

Important:
- This module does not calculate risk scores.
- It does not invent findings or runtime events.
- Dynamic behaviour is shown only when marked as observed and available.
- ML results are rendered only when supplied by the backend.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from html import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Theme colours
C_ACCENT = colors.HexColor("#0ea5e9")
C_DARK = colors.HexColor("#0f172a")
C_GRAY = colors.HexColor("#64748b")
C_GREEN = colors.HexColor("#22c55e")
C_RED = colors.HexColor("#ef4444")
C_ORANGE = colors.HexColor("#f97316")
C_YELLOW = colors.HexColor("#eab308")
C_WHITE = colors.white
C_LIGHT = colors.HexColor("#f8fafc")
C_GRID = colors.HexColor("#e2e8f0")
C_CODE_BG = colors.HexColor("#1e293b")
C_CODE_TEXT = colors.HexColor("#00ff88")


def _text(value: Any, default: str = "") -> str:
    """Return an XML-safe string suitable for a ReportLab Paragraph."""
    if value is None:
        value = default
    return escape(str(value))


def _number(value: Any, default: float = 0.0) -> float:
    """Convert a value to float without allowing malformed input to break reports."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _integer(value: Any, default: int = 0) -> int:
    """Convert a value to int without allowing malformed input to break reports."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def severity_color(level: Any):
    return {
        "critical": C_RED,
        "high": C_ORANGE,
        "medium": C_YELLOW,
        "low": C_GREEN,
        "informational": C_ACCENT,
        "info": C_ACCENT,
    }.get(str(level).lower(), C_GRAY)


def risk_color(score: Any):
    numeric_score = _number(score)
    if numeric_score >= 75:
        return C_RED
    if numeric_score >= 51:
        return C_ORANGE
    if numeric_score >= 26:
        return C_YELLOW
    return C_GREEN


def risk_label(score: Any) -> str:
    numeric_score = _number(score)
    if numeric_score >= 75:
        return "CRITICAL"
    if numeric_score >= 51:
        return "HIGH"
    if numeric_score >= 26:
        return "MEDIUM"
    return "LOW"


def _build_table(
    rows: list[list[Any]],
    widths: list[float],
    *,
    font_size: float = 9,
    header_background=C_ACCENT,
) -> Table:
    """Create a consistent table used throughout the report."""
    safe_rows = [
        [
            cell
            if isinstance(cell, Paragraph)
            else Paragraph(_text(cell), ParagraphStyle("TableCell", fontSize=font_size, leading=font_size + 2))
            for cell in row
        ]
        for row in rows
    ]

    table = Table(safe_rows, colWidths=widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), header_background),
                ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), font_size),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
                ("GRID", (0, 0), (-1, -1), 0.5, C_GRID),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _permission_name(permission: Any) -> str:
    if isinstance(permission, dict):
        return str(
            permission.get("permission")
            or permission.get("name")
            or permission.get("value")
            or "Unknown permission"
        )
    return str(permission)


def _is_dangerous_permission(permission: Any) -> bool:
    if isinstance(permission, dict) and "dangerous" in permission:
        return bool(permission.get("dangerous"))

    name = _permission_name(permission).upper()
    dangerous_keywords = (
        "SMS",
        "CAMERA",
        "CONTACTS",
        "LOCATION",
        "AUDIO",
        "MICROPHONE",
        "CALL",
        "PHONE",
        "STORAGE",
        "CALENDAR",
        "BODY_SENSORS",
        "BLUETOOTH_CONNECT",
        "POST_NOTIFICATIONS",
    )
    return any(keyword in name for keyword in dangerous_keywords)


def _first_mapping(data: dict[str, Any], *keys: str) -> dict[str, Any]:
    for key in keys:
        value = data.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _first_list(data: dict[str, Any], *keys: str) -> list[Any]:
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            return value
    return []


def _normalise_findings(data: dict[str, Any]) -> list[dict[str, Any]]:
    findings = _first_list(data, "findings", "security_findings")
    return [item for item in findings if isinstance(item, dict)]


def _normalise_dynamic(data: dict[str, Any]) -> dict[str, Any]:
    dynamic = _first_mapping(data, "dynamic", "dynamic_analysis")
    if not dynamic:
        return {}

    observed_events = dynamic.get("observed_events")
    if not isinstance(observed_events, list):
        observed_events = dynamic.get("api_calls_intercepted")
    if not isinstance(observed_events, list):
        observed_events = []

    return {
        **dynamic,
        "observed_events": observed_events,
    }


def _normalise_vt(data: dict[str, Any]) -> dict[str, Any]:
    return _first_mapping(data, "vt_result", "virustotal", "virus_total")


def _append_list(
    story: list[Any],
    values: Iterable[Any],
    style: ParagraphStyle,
    *,
    limit: int = 15,
) -> None:
    for value in list(values)[:limit]:
        story.append(Paragraph(f"• {_text(value)}", style))


def generate_pdf_report(data: dict[str, Any]) -> str:
    """
    Generate a PDF report and return its temporary file path.

    The caller is responsible for deleting the returned file after delivery.
    """
    if not isinstance(data, dict):
        raise TypeError("Report data must be a dictionary.")

    with tempfile.NamedTemporaryFile(
        suffix=".pdf",
        delete=False,
        prefix="apkguard_",
    ) as temporary_file:
        output_path = Path(temporary_file.name)

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        title="APKGuard Evidence Report",
        author="APKGuard",
        subject="Android APK security triage report",
    )

    styles = getSampleStyleSheet()

    def style(name: str, **kwargs: Any) -> ParagraphStyle:
        return ParagraphStyle(name, parent=styles["Normal"], **kwargs)

    title_style = style(
        "Title",
        fontSize=20,
        textColor=C_DARK,
        spaceAfter=2,
        fontName="Helvetica-Bold",
    )
    heading_style = style(
        "Heading",
        fontSize=12,
        textColor=C_ACCENT,
        spaceBefore=12,
        spaceAfter=5,
        fontName="Helvetica-Bold",
    )
    subheading_style = style(
        "Subheading",
        fontSize=10,
        textColor=C_DARK,
        spaceBefore=6,
        spaceAfter=3,
        fontName="Helvetica-Bold",
    )
    body_style = style("Body", fontSize=9, spaceAfter=3, leading=13)
    small_style = style(
        "Small",
        fontSize=8,
        textColor=C_GRAY,
        spaceAfter=2,
        leading=11,
    )
    warning_style = style(
        "Warning",
        fontSize=8,
        textColor=C_ORANGE,
        spaceAfter=4,
        leading=11,
    )
    code_line_style = ParagraphStyle(
        "CodeLine",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        textColor=C_CODE_TEXT,
        backColor=C_CODE_BG,
        leading=11,
    )

    story: list[Any] = []

    score = _number(data.get("risk_score"))
    filename = str(data.get("filename") or "unknown.apk")
    app_info = _first_mapping(data, "app_info", "application")
    package_name = str(
        data.get("package_name")
        or app_info.get("package")
        or app_info.get("package_name")
        or "unknown"
    )
    scan_id = str(data.get("scan_id") or data.get("job_id") or "N/A")
    timestamp = str(
        data.get("completed_at")
        or data.get("scan_time")
        or datetime.now(timezone.utc).isoformat()
    )

    hashes = _first_mapping(data, "hashes")
    vt_data = _normalise_vt(data)
    sha256 = str(
        data.get("sha256")
        or hashes.get("sha256")
        or vt_data.get("sha256")
        or "N/A"
    )
    md5 = str(
        data.get("md5")
        or hashes.get("md5")
        or vt_data.get("md5")
        or "N/A"
    )

    static_score = _number(data.get("static_score"), score)
    dynamic_score = _number(data.get("dynamic_score"))
    scoring_mode = str(data.get("scoring_mode") or "static_only")
    mode_label = {
        "static_only": "Static evidence only",
        "static_dynamic_live": "Static and observed runtime evidence",
        "static_dynamic_observed": "Static and observed runtime evidence",
    }.get(scoring_mode, scoring_mode.replace("_", " ").title())

    score_colour = risk_color(score)
    score_label = risk_label(score)

    story.extend(
        [
            Paragraph("APKGuard Evidence Report", title_style),
            Paragraph(
                "Android application security triage and evidence summary",
                small_style,
            ),
            Spacer(1, 12),
            Paragraph(f"<b>Scan ID:</b> {_text(scan_id)}", small_style),
            Paragraph(f"<b>Generated:</b> {_text(timestamp)}", small_style),
            Paragraph(f"<b>File:</b> {_text(filename)}", small_style),
            Paragraph(f"<b>Package:</b> {_text(package_name)}", small_style),
            Paragraph(f"<b>SHA-256:</b> {_text(sha256)}", small_style),
            Paragraph(f"<b>MD5 compatibility hash:</b> {_text(md5)}", small_style),
            Spacer(1, 8),
            HRFlowable(
                width="100%",
                thickness=1.5,
                color=C_ACCENT,
                spaceAfter=12,
            ),
        ]
    )

    # Risk assessment
    story.append(Paragraph("Risk Assessment", heading_style))
    risk_rows = [
        ["Metric", "Value"],
        ["Final risk score", f"{score:g}/100 — {score_label}"],
        ["Static evidence score", f"{static_score:g}/100"],
        ["Observed dynamic score", f"{dynamic_score:g}/100"],
        ["Scoring mode", mode_label],
        ["Package", package_name],
    ]

    ml_analysis = _first_mapping(data, "ml_analysis", "model_analysis")
    if ml_analysis:
        classification = (
            ml_analysis.get("ml_classification")
            or ml_analysis.get("classification")
            or "Unavailable"
        )
        confidence = ml_analysis.get("ml_confidence")
        if confidence is None:
            confidence = ml_analysis.get("confidence")
        confidence_text = (
            f"{_number(confidence):g}%"
            if confidence not in (None, "")
            else "not supplied"
        )
        risk_rows.append(
            [
                "Advisory model result",
                f"{classification} ({confidence_text}; not the final verdict)",
            ]
        )

    risk_table = _build_table(risk_rows, [5 * cm, 11 * cm])
    risk_table.setStyle(
        TableStyle(
            [
                ("TEXTCOLOR", (1, 1), (1, 1), score_colour),
                ("FONTNAME", (1, 1), (1, 1), "Helvetica-Bold"),
            ]
        )
    )
    story.extend([risk_table, Spacer(1, 8)])

    # Score breakdown
    breakdown = _first_list(data, "score_breakdown", "risk_breakdown")
    if breakdown:
        story.append(Paragraph("Score Breakdown", heading_style))
        rows = [["Category", "Points", "Evidence or rationale"]]
        for item in breakdown:
            if not isinstance(item, dict):
                continue
            rows.append(
                [
                    item.get("category", ""),
                    f"{_number(item.get('points')):+g}",
                    item.get("detail")
                    or item.get("reason")
                    or item.get("evidence")
                    or "",
                ]
            )
        if len(rows) > 1:
            story.extend(
                [
                    _build_table(rows, [5 * cm, 2.5 * cm, 8.5 * cm]),
                    Spacer(1, 8),
                ]
            )

    # Deterministic findings
    findings = _normalise_findings(data)
    if findings:
        story.append(Paragraph("Evidence-Backed Security Findings", heading_style))
        for finding in findings[:20]:
            severity = str(finding.get("severity") or "informational").lower()
            colour = severity_color(severity)
            title = finding.get("title") or finding.get("name") or "Untitled finding"
            story.append(
                Paragraph(
                    (
                        f'<b><font color="#{colour.hexval()[1:]}">'
                        f"[{_text(severity.upper())}]</font> {_text(title)}</b>"
                    ),
                    body_style,
                )
            )

            description = finding.get("description") or finding.get("summary")
            if description:
                story.append(Paragraph(_text(description), small_style))

            evidence_type = finding.get("evidence_type")
            source = finding.get("source")
            confidence = finding.get("confidence")
            metadata: list[str] = []
            if evidence_type:
                metadata.append(f"Evidence type: {evidence_type}")
            if source:
                metadata.append(f"Source: {source}")
            if confidence not in (None, ""):
                metadata.append(f"Confidence: {confidence}")
            if metadata:
                story.append(
                    Paragraph(" | ".join(_text(item) for item in metadata), small_style)
                )
        story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("Security Findings", heading_style))
        story.append(
            Paragraph(
                "No deterministic findings were supplied for this report.",
                warning_style,
            )
        )

    # Phase 3 advanced static-analysis summary
    advanced_static = _first_mapping(data, "advanced_static")
    if advanced_static:
        metrics = _first_mapping(advanced_static, "metrics")
        signing = _first_mapping(data, "signing") or _first_mapping(advanced_static, "signing")
        sbom = _first_mapping(data, "sbom") or _first_mapping(advanced_static, "sbom")
        schemes = ", ".join(str(item) for item in signing.get("detected_schemes", []))
        if not schemes and signing.get("v1_present"):
            schemes = "v1 only"
        if not schemes:
            schemes = "not structurally detected"
        advanced_rows = [
            ["Metric", "Value"],
            ["Advanced evidence", metrics.get("evidence_count", 0)],
            ["Advanced findings", metrics.get("finding_count", 0)],
            ["Exported components", metrics.get("exported_component_count", 0)],
            ["Deep-link handlers", metrics.get("deep_link_count", 0)],
            ["Signing schemes", schemes],
            ["Native libraries", metrics.get("native_library_count", 0)],
            ["Dependency fingerprints", metrics.get("dependency_count", 0)],
            ["Source-to-sink candidates", metrics.get("candidate_flow_count", 0)],
            ["SBOM components", len(sbom.get("components", []))],
        ]
        story.append(Paragraph("Advanced Static Analysis", heading_style))
        story.extend([_build_table(advanced_rows, [7 * cm, 9 * cm]), Spacer(1, 6)])
        story.append(
            Paragraph(
                "Static call paths and source/sink candidates are not runtime proof. Signing-scheme detection is "
                "structural unless verified by a controlled apksigner worker.",
                warning_style,
            )
        )

    # AI explanation — advisory only
    ai_analysis = _first_mapping(data, "ai_analysis")
    ai_summary = ai_analysis.get("threat_summary") or ai_analysis.get("summary")
    if ai_summary:
        story.append(Paragraph("AI-Assisted Explanation", heading_style))
        story.append(
            Paragraph(
                "<b>Advisory:</b> This section explains existing evidence and is "
                "not an independent malware verdict.",
                warning_style,
            )
        )
        story.append(Paragraph(_text(ai_summary), body_style))

    # Permissions
    permissions = _first_list(data, "permissions")
    if permissions:
        dangerous_permissions = [
            permission
            for permission in permissions
            if _is_dangerous_permission(permission)
        ]
        story.append(
            Paragraph(
                (
                    f"Application Permissions ({len(permissions)} total, "
                    f"{len(dangerous_permissions)} flagged for review)"
                ),
                heading_style,
            )
        )
        permission_rows = [["Permission", "Classification"]]
        for permission in permissions[:30]:
            permission_rows.append(
                [
                    _permission_name(permission),
                    "Flagged for review"
                    if _is_dangerous_permission(permission)
                    else "Not flagged by current rule",
                ]
            )
        story.extend(
            [
                _build_table(permission_rows, [11.5 * cm, 4.5 * cm], font_size=8),
                Spacer(1, 8),
            ]
        )

    # MITRE ATT&CK Mobile mappings
    mitre = _first_list(data, "mitre_mappings", "mitre_techniques", "mitre_attack")
    if mitre:
        story.append(Paragraph("MITRE ATT&CK Mobile Mappings", heading_style))
        rows = [["ID", "Technique", "Tactic", "Evidence type"]]
        for mapping in mitre[:15]:
            if not isinstance(mapping, dict):
                continue
            rows.append(
                [
                    mapping.get("id", ""),
                    mapping.get("technique", ""),
                    mapping.get("tactic", ""),
                    mapping.get("evidence_type")
                    or mapping.get("basis")
                    or "Not supplied",
                ]
            )
        if len(rows) > 1:
            story.extend(
                [
                    _build_table(
                        rows,
                        [2.2 * cm, 5.5 * cm, 4.2 * cm, 4.1 * cm],
                        font_size=8,
                    ),
                    Spacer(1, 8),
                ]
            )

    # Optional code-assistance section
    smali = _first_mapping(data, "smali_analysis")
    methods = smali.get("methods")
    if smali.get("available") and isinstance(methods, list) and methods:
        story.append(Paragraph("Code Analysis Assistance", heading_style))
        story.append(
            Paragraph(
                "Generated pseudocode is approximate and must be verified against "
                "the original bytecode.",
                warning_style,
            )
        )
        for method in methods[:8]:
            if not isinstance(method, dict):
                continue
            class_name = method.get("class_name", "")
            method_name = method.get("method_name", "")
            story.append(
                Paragraph(
                    f"<b>{_text(class_name)} → {_text(method_name)}()</b>",
                    subheading_style,
                )
            )
            summary = method.get("threat_summary")
            if summary:
                story.append(Paragraph(_text(summary), small_style))

            techniques = method.get("techniques")
            if isinstance(techniques, list) and techniques:
                story.append(
                    Paragraph(
                        f"Techniques: {_text(', '.join(map(str, techniques)))}",
                        small_style,
                    )
                )

            pseudocode = str(method.get("pseudocode") or "")
            if pseudocode:
                lines = pseudocode.splitlines()[:20]
                code_rows = [
                    [Paragraph(_text(line) or "&nbsp;", code_line_style)]
                    for line in lines
                ]
                code_table = Table(code_rows, colWidths=[16 * cm])
                code_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, -1), C_CODE_BG),
                            ("TOPPADDING", (0, 0), (-1, -1), 1),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                            ("LEFTPADDING", (0, 0), (-1, -1), 8),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ]
                    )
                )
                story.append(code_table)
            story.append(Spacer(1, 4))

    # Observed runtime behaviour only
    dynamic = _normalise_dynamic(data)
    dynamic_available = bool(dynamic.get("dynamic_available"))
    dynamic_status = str(dynamic.get("status") or "").lower()
    observed_events = dynamic.get("observed_events", [])

    if dynamic_available and observed_events:
        story.append(Paragraph("Observed Runtime Behaviour", heading_style))
        method = dynamic.get("analysis_method") or dynamic.get("mode") or "runtime"
        story.append(
            Paragraph(
                (
                    f"Method: {_text(method)} | "
                    f"Observed events: {len(observed_events)} | "
                    f"Dynamic score: {dynamic_score:g}/100"
                ),
                body_style,
            )
        )

        rows = [["Time", "Event", "Severity", "Evidence source"]]
        for event in observed_events[:25]:
            if not isinstance(event, dict):
                rows.append(["", str(event), "", "runtime"])
                continue
            rows.append(
                [
                    event.get("observed_at") or event.get("timestamp") or "",
                    event.get("title")
                    or event.get("api")
                    or event.get("event_type")
                    or event.get("event")
                    or event.get("name")
                    or "",
                    event.get("threat_level")
                    or event.get("severity")
                    or "",
                    event.get("evidence_source")
                    or event.get("source")
                    or "isolated sandbox",
                ]
            )
        story.extend(
            [
                _build_table(
                    rows,
                    [2.7 * cm, 7.3 * cm, 2.5 * cm, 3.5 * cm],
                    font_size=7.5,
                ),
                Spacer(1, 8),
            ]
        )
        sandbox_rows = [
            ["Session", dynamic.get("session_id") or "Unavailable"],
            ["AVD", dynamic.get("avd_name") or "Unavailable"],
            ["Emulator", dynamic.get("emulator_serial") or "Unavailable"],
            ["Network policy", dynamic.get("network_mode") or "Unavailable"],
            ["Instrumentation", dynamic.get("instrumentation_mode") or "Unavailable"],
            ["Cleanup confirmed", "Yes" if dynamic.get("cleanup_confirmed") else "No"],
        ]
        story.append(_build_table(sandbox_rows, [4.2 * cm, 11.8 * cm], font_size=8))
        artifacts = dynamic.get("artifacts") or []
        if artifacts:
            story.append(Spacer(1, 6))
            story.append(Paragraph("Sandbox Artifacts", subheading_style))
            artifact_rows = [["Type", "File", "SHA-256"]]
            for artifact in artifacts[:20]:
                artifact_rows.append(
                    [
                        artifact.get("artifact_type", ""),
                        artifact.get("filename", ""),
                        artifact.get("sha256", "")[:24],
                    ]
                )
            story.append(_build_table(artifact_rows, [3.2 * cm, 6.3 * cm, 6.5 * cm], font_size=7.2))
    else:
        story.append(Paragraph("Dynamic Analysis", heading_style))
        reason = (
            dynamic.get("reason")
            or dynamic.get("message")
            or "No verified runtime evidence was captured for this scan."
        )
        if dynamic_status in {"not_executed", "skipped", "unavailable", ""}:
            story.append(Paragraph(_text(reason), warning_style))
        else:
            story.append(
                Paragraph(
                    f"Dynamic stage status: {_text(dynamic_status)}. {_text(reason)}",
                    warning_style,
                )
            )

    # Threat intelligence / VirusTotal
    if vt_data:
        story.append(Paragraph("VirusTotal Hash Reputation", heading_style))
        status = str(vt_data.get("status") or "").lower()
        error = vt_data.get("error")

        if error:
            story.append(
                Paragraph(
                    f"Lookup unavailable or failed: {_text(error)}",
                    warning_style,
                )
            )
        elif status in {"not_found", "unknown"}:
            story.append(
                Paragraph(
                    "The SHA-256 hash was not found in the configured reputation service. "
                    "This does not mean the APK is safe.",
                    warning_style,
                )
            )
        elif status in {"disabled", "not_configured", "skipped"}:
            story.append(
                Paragraph(
                    "VirusTotal lookup was not performed for this scan.",
                    warning_style,
                )
            )
        elif vt_data.get("detected") is not None:
            detected = _integer(vt_data.get("detected"))
            total = _integer(vt_data.get("total"))
            story.append(
                Paragraph(
                    (
                        f"<b>{detected}/{total} engines reported detections.</b> "
                        "Reputation information is enrichment and not the sole verdict."
                    ),
                    body_style,
                )
            )
        else:
            story.append(
                Paragraph(
                    "No usable VirusTotal reputation result was supplied.",
                    warning_style,
                )
            )

    # ML validation information — never hard-code benchmark claims
    if ml_analysis:
        validation = ml_analysis.get("validation") or ml_analysis.get(
            "validation_scope"
        )
        metrics = ml_analysis.get("metrics")
        story.append(Paragraph("Machine-Learning Advisory", heading_style))
        story.append(
            Paragraph(
                (
                    "Model output is advisory and does not replace deterministic "
                    "evidence or analyst review."
                ),
                warning_style,
            )
        )
        if validation:
            story.append(
                Paragraph(f"Validation scope: {_text(validation)}", small_style)
            )
        if isinstance(metrics, dict) and metrics:
            metric_rows = [["Metric", "Value"]]
            for name, value in metrics.items():
                metric_rows.append([str(name), str(value)])
            story.append(_build_table(metric_rows, [8 * cm, 8 * cm], font_size=8))

    # Limitations and provenance
    story.append(Paragraph("Report Limitations", heading_style))
    limitations = data.get("limitations")
    if isinstance(limitations, list) and limitations:
        _append_list(story, limitations, small_style, limit=20)
    else:
        default_limitations = [
            "A low score or absent reputation detection does not prove that an APK is safe.",
            "Static indicators may be present in unreachable or unused code.",
            "Runtime analysis covers only behaviours exercised during the configured execution window.",
            "AI-generated explanations and pseudocode require analyst verification.",
            "This report is a triage artefact, not a substitute for complete manual reverse engineering.",
        ]
        _append_list(story, default_limitations, small_style)

    analyzer_version = data.get("analyzer_version") or data.get("version") or "N/A"
    policy_version = data.get("scoring_policy_version") or "N/A"

    story.extend(
        [
            Spacer(1, 12),
            HRFlowable(width="100%", thickness=0.5, color=C_GRAY),
            Spacer(1, 4),
            Paragraph(
                (
                    f"Generated by APKGuard | Analyzer version: "
                    f"{_text(analyzer_version)} | Scoring policy: "
                    f"{_text(policy_version)}"
                ),
                style(
                    "Footer",
                    fontSize=7.5,
                    textColor=C_GRAY,
                    alignment=TA_CENTER,
                ),
            ),
        ]
    )

    document.build(story)
    return str(output_path)
