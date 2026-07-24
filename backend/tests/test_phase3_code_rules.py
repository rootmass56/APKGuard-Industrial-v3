from app.static_analysis.code import (
    analyze_code_strings,
    analyze_secrets,
    candidate_string_flows,
    identify_sdks,
)


def test_code_rules_and_secret_redaction():
    # Build a synthetic Google-style key at runtime so the analyzer still
    # exercises its detection/redaction path without committing a token-shaped
    # literal that repository secret scanners can mistake for a real key.
    synthetic_google_key = "".join(
        (
            "AI",
            "za",
            "12345678901234567890123456789012345",
        )
    )

    strings = {
        "classes.dex": [
            "DexClassLoader",
            "AES/ECB/PKCS5Padding",
            "setJavaScriptEnabled",
            "addJavascriptInterface",
            synthetic_google_key,
            "getDeviceId",
            "okhttp3",
        ]
    }

    rules = analyze_code_strings(strings)
    ids = {item["rule_id"] for item in rules["matches"]}
    assert "CODE-DYNAMIC-DEX" in ids
    assert "CRYPTO-ECB" in ids
    assert "WEBVIEW-JS-INTERFACE" in ids

    secrets = analyze_secrets(strings)
    assert secrets["findings"]
    assert synthetic_google_key not in str(secrets["findings"])
    assert "AIza1234" not in str(secrets["findings"])
    assert identify_sdks(strings)[0]["name"] == "OkHttp"
    assert candidate_string_flows(strings)


def test_rule_catalogue_uses_verified_standard_mappings():
    from app.static_analysis.rules import CODE_RULES

    rules = {rule.rule_id: rule for rule in CODE_RULES}
    assert rules["WEBVIEW-UNIVERSAL-FILE-ACCESS"].maswe == ("MASWE-0069",)
    assert "T1628" not in rules["ANTI-DEBUG"].attack
