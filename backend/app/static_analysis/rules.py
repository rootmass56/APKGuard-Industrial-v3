"""Versioned Phase 3 rule catalogue and standards mappings."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CodeRule:
    rule_id: str
    title: str
    description: str
    severity: str
    category: str
    patterns: tuple[str, ...]
    confidence: float
    risk_points: int
    cwe: tuple[str, ...] = ()
    maswe: tuple[str, ...] = ()
    attack: tuple[str, ...] = ()
    remediation: tuple[str, ...] = ()


CODE_RULES = (
    CodeRule(
        "TLS-ALLOW-ALL-HOSTNAME",
        "Potential permissive hostname verification",
        "Code strings reference permissive hostname-verification constructs.",
        "HIGH",
        "tls",
        ("ALLOW_ALL_HOSTNAME_VERIFIER", "AllowAllHostnameVerifier"),
        0.82,
        12,
        ("CWE-297",),
        ("MASWE-0052",),
        remediation=("Use strict platform hostname verification.",),
    ),
    CodeRule(
        "TLS-SSL-ERROR-PROCEED",
        "Potential WebView SSL error bypass",
        "The APK contains both SSL-error callback and proceed indicators.",
        "HIGH",
        "webview",
        ("onReceivedSslError", "proceed()"),
        0.72,
        12,
        ("CWE-295",),
        ("MASWE-0052",),
        remediation=("Cancel WebView loads on certificate errors.",),
    ),
    CodeRule(
        "WEBVIEW-JS-INTERFACE",
        "JavaScript bridge exposed to WebView content",
        "JavaScript and addJavascriptInterface indicators occur in the APK.",
        "HIGH",
        "webview",
        ("setJavaScriptEnabled", "addJavascriptInterface"),
        0.78,
        10,
        ("CWE-749",),
        ("MASWE-0068",),
        remediation=("Expose only minimal annotated methods and restrict loaded origins.",),
    ),
    CodeRule(
        "WEBVIEW-UNIVERSAL-FILE-ACCESS",
        "Universal file URL access indicator",
        "WebView universal file-URL access API is referenced.",
        "HIGH",
        "webview",
        ("setAllowUniversalAccessFromFileURLs",),
        0.88,
        11,
        ("CWE-200",),
        ("MASWE-0069",),
        remediation=("Disable universal access from file URLs.",),
    ),
    CodeRule(
        "CRYPTO-ECB",
        "ECB-mode cryptography indicator",
        "A transformation string indicates ECB mode, which does not provide semantic security.",
        "HIGH",
        "cryptography",
        ("AES/ECB", "DES/ECB"),
        0.92,
        10,
        ("CWE-327",),
        ("MASWE-0020",),
        remediation=("Use an authenticated mode such as AES-GCM with unique nonces.",),
    ),
    CodeRule(
        "CRYPTO-WEAK-ALGORITHM",
        "Weak cryptographic algorithm indicator",
        "The APK references a deprecated cryptographic primitive.",
        "MEDIUM",
        "cryptography",
        ("DESede", "RC4", "ARCFOUR", "Cipher.getInstance(\"DES"),
        0.78,
        7,
        ("CWE-327",),
        ("MASWE-0020",),
        remediation=("Replace deprecated primitives with current authenticated encryption.",),
    ),
    CodeRule(
        "CODE-DYNAMIC-DEX",
        "Dynamic code-loading indicator",
        "The APK references Android dynamic class-loading APIs.",
        "HIGH",
        "dynamic_code",
        ("DexClassLoader", "InMemoryDexClassLoader", "loadDex"),
        0.9,
        13,
        ("CWE-829",),
        attack=("T1407",),
        remediation=("Load only signed, integrity-verified code from trusted internal storage.",),
    ),
    CodeRule(
        "CODE-COMMAND-EXECUTION",
        "Command-execution API indicator",
        "Runtime or process command-execution constructs are referenced.",
        "HIGH",
        "command_execution",
        ("Runtime.exec", "ProcessBuilder", "/system/bin/sh"),
        0.86,
        12,
        ("CWE-78",),
        attack=("T1623",),
        remediation=("Avoid shell invocation and strictly validate any command arguments.",),
    ),
    CodeRule(
        "CODE-REFLECTION",
        "Reflection indicator",
        "Reflection APIs are referenced; reachability and intent require further review.",
        "LOW",
        "reflection",
        ("Class.forName", "java/lang/reflect/Method", "Method.invoke"),
        0.68,
        3,
        ("CWE-470",),
        remediation=("Minimize reflection and constrain dynamically resolved classes and methods.",),
    ),
    CodeRule(
        "ANTI-DEBUG",
        "Anti-debugging indicator",
        "The APK references debugger or tracing detection constructs.",
        "MEDIUM",
        "anti_analysis",
        ("isDebuggerConnected", "TracerPid", "ptrace"),
        0.72,
        6,
        remediation=("Document legitimate anti-tamper controls and review combinations with other evasive behavior.",),
    ),
    CodeRule(
        "INSTALL-PACKAGE",
        "Package-installation API indicator",
        "The APK references package installation or unknown-source capabilities.",
        "MEDIUM",
        "package_installation",
        ("REQUEST_INSTALL_PACKAGES", "PackageInstaller"),
        0.82,
        7,
        attack=("T1476",),
        remediation=("Require explicit user intent and verify packages before installation.",),
    ),
)

SOURCE_PATTERNS = {
    "device_identifier": ("getDeviceId", "getImei", "getSubscriberId", "ANDROID_ID"),
    "location": ("getLastKnownLocation", "requestLocationUpdates"),
    "contacts": ("ContactsContract", "READ_CONTACTS"),
    "sms": ("READ_SMS", "getMessageBody"),
    "account": ("AccountManager", "getAccounts"),
}

SINK_PATTERNS = {
    "network": ("HttpURLConnection", "okhttp3", "java/net/Socket", "retrofit2"),
    "sms": ("sendTextMessage",),
    "file": ("FileOutputStream", "openFileOutput"),
    "logging": ("android/util/Log", "System.out"),
}
