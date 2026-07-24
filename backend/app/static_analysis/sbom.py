"""CycloneDX-style SBOM generation with explicit version limitations."""

from __future__ import annotations

import uuid
from typing import Any


def build_sbom(
    *,
    apk_sha256: str,
    package_name: str | None,
    filename: str,
    sdks: list[dict[str, Any]],
    native_libraries: list[dict[str, Any]],
) -> dict[str, Any]:
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"apkguard:{apk_sha256}")
    components: list[dict[str, Any]] = []
    for sdk in sdks:
        components.append(
            {
                "type": "library",
                "name": sdk["name"],
                "version": sdk.get("version") or "unknown",
                "purl": sdk.get("purl"),
                "properties": [
                    {"name": "apkguard:version_status", "value": sdk.get("version_status", "not_determined")},
                    {"name": "apkguard:evidence", "value": sdk.get("evidence", "")},
                ],
            }
        )
    for native in native_libraries:
        component = {
            "type": "library",
            "name": native["path"].split("/")[-1],
            "version": "unknown",
            "hashes": [{"alg": "SHA-256", "content": native.get("sha256", "")}],
            "properties": [
                {"name": "apkguard:path", "value": native["path"]},
                {"name": "apkguard:abi", "value": str(native.get("abi") or "unknown")},
                {"name": "apkguard:machine", "value": str(native.get("machine") or "unknown")},
            ],
        }
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "APKGuard", "version": "3.2.0-phase3"}]},
            "component": {
                "type": "application",
                "name": package_name or filename,
                "version": "unknown",
                "hashes": [{"alg": "SHA-256", "content": apk_sha256}],
            },
        },
        "components": sorted(components, key=lambda item: (item["type"], item["name"])),
        "properties": [
            {
                "name": "apkguard:limitation",
                "value": (
                    "Component versions are unknown unless deterministically recovered; no CVE claim is made "
                    "without a version."
                ),
            }
        ],
    }
