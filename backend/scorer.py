SEVERITY_LEVELS = {
    "CRITICAL": {"min": 75, "color": "#FF0000", "label": "CRITICAL"},
    "HIGH":     {"min": 51, "color": "#FF6600", "label": "HIGH"},
    "MEDIUM":   {"min": 26, "color": "#FFAA00", "label": "MEDIUM"},
    "LOW":      {"min": 0,  "color": "#00AA00", "label": "LOW"},
}

def calculate_score(analysis, behavioral=None, vt=None):
    score = 0
    breakdown = []
    dangerous_perms_list = analysis.get("permissions", {}).get("dangerous", [])
    perm_score = min(sum(p["score"] for p in dangerous_perms_list), 30)
    if perm_score > 0:
        breakdown.append({"category": "Dangerous Permissions", "points": perm_score, "detail": f"{len(dangerous_perms_list)} dangerous permissions found"})
    score += perm_score
    apis = analysis.get("suspicious_apis", [])
    api_score = min(sum(a["score"] for a in apis), 25)
    breakdown.append({"category": "Suspicious API Calls", "points": api_score, "detail": f"{len(apis)} suspicious APIs detected" if apis else "No suspicious APIs detected"})
    score += api_score
    urls = analysis.get("urls_ips", {}).get("urls", [])
    ips = analysis.get("urls_ips", {}).get("ips", [])
    url_score = min(len(urls) * 2 + len(ips) * 4, 15)
    breakdown.append({"category": "Hardcoded URLs/IPs", "points": url_score, "detail": f"{len(urls)} URLs and {len(ips)} IPs found" if (urls or ips) else "No hardcoded URLs/IPs found"})
    score += url_score
    obf = analysis.get("obfuscation", {})
    obf_score = min(obf.get("score", 0), 15)
    if obf_score > 0:
        breakdown.append({"category": "Code Obfuscation", "points": obf_score, "detail": "; ".join(obf.get("indicators", ["Obfuscation detected"]))})
    score += obf_score
    bi = analysis.get("banking_indicators", [])
    bi_score = min(len(bi) * 3, 10)
    breakdown.append({"category": "Banking Trojan Indicators", "points": bi_score, "detail": f"Matched: {', '.join(bi)}" if bi else "No banking trojan indicators"})
    score += bi_score
    libs = analysis.get("native_libs", [])
    lib_score = min(len(libs) * 2, 5)
    if lib_score > 0:
        breakdown.append({"category": "Native Libraries", "points": lib_score, "detail": f"{len(libs)} .so files found"})
    score += lib_score
    overrides = []
    dp = [p["permission"] for p in dangerous_perms_list]
    accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in dp
    overlay = "android.permission.SYSTEM_ALERT_WINDOW" in dp
    sms_read = "android.permission.READ_SMS" in dp
    sms_receive = "android.permission.RECEIVE_SMS" in dp
    if accessibility and overlay:
        score = max(score, 80)
        overrides.append("Accessibility + Overlay = Banking Trojan forced CRITICAL")
    if sms_read and sms_receive:
        score = max(score, 75)
        overrides.append("SMS read + intercept = OTP theft forced CRITICAL")
    score = min(score, 100)
    severity = "LOW"
    for level, cfg in SEVERITY_LEVELS.items():
        if score >= cfg["min"]:
            severity = level
            break
    mitre = []
    api_names = [a["api"] for a in apis]
    if "onAccessibilityEvent" in api_names or accessibility:
        mitre.append({"id": "T1417", "name": "Input Capture", "tactic": "Collection"})
    if overlay:
        mitre.append({"id": "T1416", "name": "URI Hijacking", "tactic": "Credential Access"})
    if sms_read or sms_receive:
        mitre.append({"id": "T1412", "name": "Capture SMS Messages", "tactic": "Collection"})
    if "DexClassLoader" in api_names:
        mitre.append({"id": "T1407", "name": "Download New Code at Runtime", "tactic": "Defense Evasion"})
    if "Runtime.exec" in api_names:
        mitre.append({"id": "T1623", "name": "Command and Scripting Interpreter", "tactic": "Execution"})
    if obf.get("detected"):
        mitre.append({"id": "T1406", "name": "Obfuscated Files", "tactic": "Defense Evasion"})
    if "getDeviceId" in api_names or "getSubscriberId" in api_names:
        mitre.append({"id": "T1426", "name": "System Information Discovery", "tactic": "Discovery"})
    # Expanded MITRE mapping from permissions
    dp_list = str(analysis.get("permissions", [])) # Foolproof string match
    if "READ_SMS" in str(dp_list) or "RECEIVE_SMS" in str(dp_list):
        if not any(m.get("id")=="T1412" for m in mitre):
            mitre.append({"id": "T1412", "name": "Capture SMS Messages", "tactic": "Collection"})
    if "ACCESS_FINE_LOCATION" in str(dp_list) or "ACCESS_COARSE_LOCATION" in str(dp_list):
        mitre.append({"id": "T1430", "name": "Location Tracking", "tactic": "Collection"})
    if "CAMERA" in str(dp_list) or "RECORD_AUDIO" in str(dp_list):
        mitre.append({"id": "T1429", "name": "Capture Camera/Audio", "tactic": "Collection"})
    if "READ_CONTACTS" in str(dp_list):
        mitre.append({"id": "T1432", "name": "Access Contact List", "tactic": "Collection"})
    if "READ_CALL_LOG" in str(dp_list):
        mitre.append({"id": "T1433", "name": "Access Call Log", "tactic": "Collection"})
    if "SEND_SMS" in str(dp_list):
        mitre.append({"id": "T1438", "name": "Exfiltration Over SMS", "tactic": "Exfiltration"})
    if "RECEIVE_BOOT_COMPLETED" in str(dp_list):
        mitre.append({"id": "T1402", "name": "Boot or Logon Initialization", "tactic": "Persistence"})
    return {"score": score, "severity": severity, "color": SEVERITY_LEVELS[severity]["color"], "breakdown": breakdown, "overrides": overrides, "mitre": mitre}


def calculate_dynamic_score(dynamic_result):
    """
    Calculate dynamic risk score from PURE Frida/runtime data only.
    This is completely independent from static analysis.
    """
    if not dynamic_result or not dynamic_result.get("dynamic_available"):
        return {"dynamic_score": 0, "dynamic_available": False, "dynamic_breakdown": []}

    score = 0
    breakdown = []
    method = dynamic_result.get("analysis_method", "unknown")

    # Only use runtime-captured data
    api_calls = dynamic_result.get("api_calls_intercepted", [])
    file_ops = dynamic_result.get("file_operations", [])
    crypto_ops = dynamic_result.get("crypto_operations", [])
    network_calls = dynamic_result.get("network_calls", [])

    # Score based on intercepted API calls severity
    critical_apis = [a for a in api_calls if a.get("threat_level") == "critical"]
    high_apis = [a for a in api_calls if a.get("threat_level") == "high"]
    medium_apis = [a for a in api_calls if a.get("threat_level") == "medium"]

    api_score = min(len(critical_apis)*8 + len(high_apis)*5 + len(medium_apis)*2, 40)
    if api_score > 0:
        breakdown.append({"category": "Runtime API Intercepts", "points": api_score,
            "detail": f"{len(critical_apis)} critical, {len(high_apis)} high, {len(medium_apis)} medium"})
    score += api_score

    # Score file operations
    file_score = min(len(file_ops) * 5, 20)
    if file_score > 0:
        breakdown.append({"category": "Covert File Operations", "points": file_score,
            "detail": f"{len(file_ops)} file operations detected"})
    score += file_score

    # Score crypto operations
    crypto_score = min(len(crypto_ops) * 8, 20)
    if crypto_score > 0:
        breakdown.append({"category": "Runtime Crypto Operations", "points": crypto_score,
            "detail": f"{len(crypto_ops)} crypto ops intercepted"})
    score += crypto_score

    # Score network calls
    net_score = min(len(network_calls) * 5, 20)
    if net_score > 0:
        breakdown.append({"category": "Network Calls", "points": net_score,
            "detail": f"{len(network_calls)} network connections"})
    score += net_score

    score = min(score, 100)

    return {
        "dynamic_score": score,
        "dynamic_available": True,
        "dynamic_breakdown": breakdown,
        "analysis_method": method,
        "is_live_frida": method == "frida_live_instrumentation"
    }

def calculate_final_score(static_result, dynamic_result=None):
    """Combine static score with *observed* dynamic score only.

    Sprint 0 correctness rule: simulated or inferred behaviour is never used as
    dynamic evidence. If live runtime instrumentation is unavailable, the final
    score is the static score.
    """
    static_score = static_result.get("score", 0)

    if not dynamic_result or not dynamic_result.get("dynamic_available"):
        return {
            "final_score": static_score,
            "static_score": static_score,
            "dynamic_score": 0,
            "scoring_mode": "static_only",
            "breakdown": static_result.get("breakdown", []),
            "dynamic_breakdown": [],
        }

    dynamic_data = calculate_dynamic_score(dynamic_result)
    if not dynamic_data.get("is_live_frida"):
        return {
            "final_score": static_score,
            "static_score": static_score,
            "dynamic_score": 0,
            "scoring_mode": "static_only_dynamic_untrusted",
            "breakdown": static_result.get("breakdown", []),
            "dynamic_breakdown": [],
        }

    dynamic_score = dynamic_data["dynamic_score"]
    final = min(round(0.6 * static_score + 0.4 * dynamic_score), 100)

    return {
        "final_score": final,
        "static_score": static_score,
        "dynamic_score": dynamic_score,
        "scoring_mode": "static_dynamic_live",
        "breakdown": static_result.get("breakdown", []),
        "dynamic_breakdown": dynamic_data.get("dynamic_breakdown", []),
    }
