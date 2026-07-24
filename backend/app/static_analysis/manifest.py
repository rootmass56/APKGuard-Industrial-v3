"""Manifest, component exposure, deep-link, and network-security analysis."""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

log = logging.getLogger("apkguard.static.manifest")
ANDROID_NS = "http://schemas.android.com/apk/res/android"
A = f"{{{ANDROID_NS}}}"


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.strip().lower() == "true"


def _root_from_apk(apk: Any) -> Any | None:
    if apk is None:
        return None
    try:
        root = apk.get_android_manifest_xml()
        if root is not None:
            return root
        axml = apk.get_android_manifest_axml()
        return axml.get_xml_obj() if axml is not None else None
    except (AttributeError, TypeError, ValueError) as exc:
        log.debug("Androguard manifest object unavailable: %s", exc)
        return None


def _root_from_plain_xml(path: Path) -> Any | None:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            raw = archive.read("AndroidManifest.xml")
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile):
        return None
    stripped = raw.lstrip()
    if not stripped.startswith(b"<"):
        return None
    try:
        return DefusedET.fromstring(raw)
    except (DefusedET.ParseError, DefusedXmlException, ValueError):
        return None


def _attr(element: Any, name: str) -> str | None:
    return element.get(f"{A}{name}") or element.get(name)


def _intent_filter_details(element: Any) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for intent_filter in element.findall("intent-filter"):
        actions = sorted({_attr(item, "name") or "" for item in intent_filter.findall("action")} - {""})
        categories = sorted({_attr(item, "name") or "" for item in intent_filter.findall("category")} - {""})
        data_items: list[dict[str, Any]] = []
        for data in intent_filter.findall("data"):
            data_items.append(
                {
                    key: value
                    for key in ("scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType")
                    if (value := _attr(data, key)) is not None
                }
            )
        output.append(
            {
                "actions": actions,
                "categories": categories,
                "data": data_items,
                "auto_verify": _bool(_attr(intent_filter, "autoVerify")),
            }
        )
    return output


def _component(element: Any, component_type: str) -> dict[str, Any]:
    filters = _intent_filter_details(element)
    explicit_exported = _bool(_attr(element, "exported"))
    exported = explicit_exported if explicit_exported is not None else bool(filters)
    return {
        "type": component_type,
        "name": _attr(element, "name") or "",
        "exported": exported,
        "exported_explicit": explicit_exported,
        "implicit_export_reason": explicit_exported is None and bool(filters),
        "permission": _attr(element, "permission"),
        "read_permission": _attr(element, "readPermission"),
        "write_permission": _attr(element, "writePermission"),
        "authorities": _attr(element, "authorities"),
        "grant_uri_permissions": _bool(_attr(element, "grantUriPermissions")),
        "enabled": _bool(_attr(element, "enabled")),
        "process": _attr(element, "process"),
        "intent_filters": filters,
    }


def _network_security_config(path: Path, reference: str | None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "declared": bool(reference),
        "reference": reference,
        "parsed": False,
        "cleartext_permitted": [],
        "user_trust_anchors": [],
        "debug_overrides": False,
        "pin_sets": [],
    }
    if not reference or not reference.startswith("@xml/"):
        return report
    entry = f"res/xml/{reference.split('/', 1)[1]}.xml"
    try:
        with zipfile.ZipFile(path, "r") as archive:
            raw = archive.read(entry)
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile):
        return report
    if not raw.lstrip().startswith(b"<"):
        report["parse_status"] = "binary_xml_requires_androguard_resource_decoder"
        return report
    try:
        root = DefusedET.fromstring(raw)
    except (DefusedET.ParseError, DefusedXmlException, ValueError):
        return report
    report["parsed"] = True
    for node in root.iter():
        tag = node.tag.split("}")[-1]
        if tag in {"base-config", "domain-config"} and _attr(node, "cleartextTrafficPermitted") == "true":
            domains = [item.text or "" for item in node.findall("domain")]
            report["cleartext_permitted"].append({"scope": tag, "domains": domains})
        if tag == "certificates" and _attr(node, "src") == "user":
            report["user_trust_anchors"].append("user")
        if tag == "debug-overrides":
            report["debug_overrides"] = True
        if tag == "pin-set":
            report["pin_sets"].append(
                {
                    "expiration": _attr(node, "expiration"),
                    "pin_count": len(node.findall("pin")),
                }
            )
    return report


def analyze_manifest(path: Path, apk: Any = None) -> dict[str, Any]:
    root = _root_from_apk(apk)
    if root is None:
        root = _root_from_plain_xml(path)
    if root is None:
        return {
            "available": False,
            "status": "binary_manifest_not_decoded",
            "components": [],
            "deep_links": [],
            "application": {},
            "limitations": ["Manifest details require Androguard when AndroidManifest.xml is binary AXML."],
        }
    uses_sdk = root.find("uses-sdk")
    target_sdk = _attr(uses_sdk, "targetSdkVersion") if uses_sdk is not None else None
    min_sdk = _attr(uses_sdk, "minSdkVersion") if uses_sdk is not None else None
    application = root.find("application")
    app_settings: dict[str, Any] = {}
    components: list[dict[str, Any]] = []
    if application is not None:
        app_settings = {
            "debuggable": _bool(_attr(application, "debuggable")),
            "allow_backup": _bool(_attr(application, "allowBackup")),
            "uses_cleartext_traffic": _bool(_attr(application, "usesCleartextTraffic")),
            "network_security_config": _attr(application, "networkSecurityConfig"),
            "test_only": _bool(_attr(application, "testOnly")),
            "request_legacy_external_storage": _bool(_attr(application, "requestLegacyExternalStorage")),
            "extract_native_libs": _bool(_attr(application, "extractNativeLibs")),
        }
        for component_type in ("activity", "activity-alias", "service", "receiver", "provider"):
            components.extend(_component(item, component_type) for item in application.findall(component_type))
    permissions = sorted(
        {
            _attr(item, "name") or ""
            for tag in ("uses-permission", "uses-permission-sdk-23")
            for item in root.findall(tag)
        }
        - {""}
    )
    deep_links: list[dict[str, Any]] = []
    for component in components:
        for intent_filter in component["intent_filters"]:
            for data in intent_filter["data"]:
                if data.get("scheme"):
                    deep_links.append(
                        {
                            "component": component["name"],
                            "component_type": component["type"],
                            "exported": component["exported"],
                            "scheme": data.get("scheme"),
                            "host": data.get("host"),
                            "path": data.get("path") or data.get("pathPrefix") or data.get("pathPattern"),
                            "auto_verify": intent_filter.get("auto_verify"),
                            "actions": intent_filter.get("actions", []),
                            "categories": intent_filter.get("categories", []),
                        }
                    )
    return {
        "available": True,
        "status": "parsed",
        "package": root.get("package"),
        "target_sdk": target_sdk,
        "min_sdk": min_sdk,
        "permissions": permissions,
        "application": app_settings,
        "components": components,
        "exported_components": [item for item in components if item["exported"]],
        "deep_links": deep_links,
        "network_security": _network_security_config(path, app_settings.get("network_security_config")),
        "limitations": [
            "Exported-state analysis describes manifest exposure; it does not prove exploitability.",
            "Network-security XML is parsed only when stored as plain XML or decoded by supported tooling.",
        ],
    }
