from __future__ import annotations

import zipfile
from pathlib import Path

from app.static_analysis.manifest import analyze_manifest

MANIFEST = """<?xml version='1.0' encoding='utf-8'?>
<manifest xmlns:android='http://schemas.android.com/apk/res/android' package='com.example.risky'>
  <uses-sdk android:minSdkVersion='24' android:targetSdkVersion='30'/>
  <uses-permission android:name='android.permission.READ_SMS'/>
  <application android:debuggable='true' android:allowBackup='true' android:usesCleartextTraffic='true'
      android:networkSecurityConfig='@xml/network_security_config'>
    <service android:name='.ExportedService' android:exported='true'/>
    <activity android:name='.DeepLinkActivity' android:exported='true'>
      <intent-filter>
        <action android:name='android.intent.action.VIEW'/>
        <category android:name='android.intent.category.BROWSABLE'/>
        <data android:scheme='riskydemo'/>
      </intent-filter>
    </activity>
  </application>
</manifest>
"""
NETSEC = """<network-security-config>
  <base-config cleartextTrafficPermitted='true'>
    <trust-anchors><certificates src='user'/></trust-anchors>
  </base-config>
</network-security-config>"""


def test_manifest_attack_surface_and_network_config(tmp_path: Path):
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
        archive.writestr("res/xml/network_security_config.xml", NETSEC)
        archive.writestr("classes.dex", b"dex")
    report = analyze_manifest(apk)
    assert report["available"] is True
    assert report["application"]["debuggable"] is True
    assert len(report["exported_components"]) == 2
    assert report["deep_links"][0]["scheme"] == "riskydemo"
    assert report["network_security"]["cleartext_permitted"]
    assert report["network_security"]["user_trust_anchors"] == ["user"]
