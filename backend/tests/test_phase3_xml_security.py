"""Security regression tests for untrusted XML parsing in Phase 3."""

from __future__ import annotations

import zipfile
from pathlib import Path

from app.static_analysis.manifest import _network_security_config, _root_from_plain_xml


MALICIOUS_MANIFEST = b"""<?xml version='1.0' encoding='utf-8'?>
<!DOCTYPE manifest [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
<manifest package='com.example.securitytest'>&xxe;</manifest>
"""

MALICIOUS_NETWORK_CONFIG = b"""<?xml version='1.0' encoding='utf-8'?>
<!DOCTYPE network-security-config [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
<network-security-config>
  <base-config cleartextTrafficPermitted='false'>&xxe;</base-config>
</network-security-config>
"""


def _write_archive(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)


def test_manifest_parser_rejects_external_entities(tmp_path: Path) -> None:
    apk_path = tmp_path / "malicious-manifest.apk"
    _write_archive(apk_path, {"AndroidManifest.xml": MALICIOUS_MANIFEST})

    assert _root_from_plain_xml(apk_path) is None


def test_network_security_parser_rejects_external_entities(tmp_path: Path) -> None:
    apk_path = tmp_path / "malicious-network-config.apk"
    _write_archive(
        apk_path,
        {"res/xml/network_security_config.xml": MALICIOUS_NETWORK_CONFIG},
    )

    report = _network_security_config(apk_path, "@xml/network_security_config")

    assert report["declared"] is True
    assert report["parsed"] is False
    assert report["cleartext_permitted"] == []
    assert report["user_trust_anchors"] == []
