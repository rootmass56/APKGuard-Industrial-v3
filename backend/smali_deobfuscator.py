"""
APKGuard AI — smali_deobfuscator.py
Extracts Smali bytecode from crypto/network methods and uses
Groq LLaMA 3.3 70B to translate to Python pseudocode.
"""
import os
import requests
from dotenv import load_dotenv
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

KEYWORDS = [
    'Cipher', 'encrypt', 'decrypt', 'Socket', 'HttpURLConnection',
    'HttpsURLConnection', 'SSLContext', 'Runtime', 'exec',
    'crypto', 'SecretKey', 'KeyGenerator', 'TrustManager'
]

def extract_smali_methods(apk_path: str, max_methods: int = 5) -> list:
    """
    Extract Smali bytecode from methods that reference crypto/network APIs.
    Returns list of dicts with class, method, smali text.
    """
    try:
        from androguard.misc import AnalyzeAPK
        a, d, dx = AnalyzeAPK(apk_path)
        dex = d[0] if isinstance(d, list) else d
    except Exception as e:
        return [{"error": str(e)}]

    found = []
    for cls in dex.get_classes():
        for method in cls.get_methods():
            code = method.get_code()
            if code is None:
                continue
            instrs = list(method.get_instructions())
            instr_str = ' '.join(str(i) for i in instrs)
            if not any(k in instr_str for k in KEYWORDS):
                continue

            smali_lines = [str(i) for i in instrs]
            found.append({
                "class_name": method.get_class_name(),
                "method_name": method.get_name(),
                "descriptor": method.get_descriptor(),
                "smali_lines": smali_lines,
                "smali_text": '\n'.join(smali_lines),
                "instruction_count": len(smali_lines)
            })
            if len(found) >= max_methods:
                break
        if len(found) >= max_methods:
            break

    return found


def deobfuscate_with_llm(smali_text: str, class_name: str, method_name: str) -> dict:
    """
    Send Smali bytecode to Groq LLaMA 3.3 70B.
    Returns Python pseudocode translation and threat summary.
    """
    if not GROQ_API_KEY:
        return {"error": "GROQ_API_KEY not set", "pseudocode": "", "threat_summary": ""}

    prompt = f"""You are a malware reverse engineer. Translate this Android Smali bytecode to readable Python pseudocode.

Class: {class_name}
Method: {method_name}

Smali bytecode:
{smali_text[:2000]}

Respond in this exact JSON format (no markdown, no backticks):
{{
  "pseudocode": "# Python pseudocode here\\ndef method_name():\\n    ...",
  "threat_summary": "One sentence describing what this code does and why it is suspicious",
  "threat_level": "critical|high|medium|low",
  "techniques": ["list", "of", "techniques", "used"]
}}"""

    try:
        resp = requests.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 800,
                "temperature": 0.1
            },
            timeout=30
        )
        raw = resp.json()["choices"][0]["message"]["content"].strip()
        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        import json
        return json.loads(raw.strip())
    except Exception as e:
        return {
            "pseudocode": "# LLM translation unavailable",
            "threat_summary": f"Error: {e}",
            "threat_level": "unknown",
            "techniques": []
        }


def run_smali_deobfuscation(apk_path: str) -> dict:
    """
    Full pipeline: extract Smali → translate each method → return results.
    """
    methods = extract_smali_methods(apk_path, max_methods=5)
    if not methods or "error" in methods[0]:
        return {"available": False, "methods": [], "error": methods[0].get("error", "unknown")}

    results = []
    for m in methods:
        translation = deobfuscate_with_llm(
            m["smali_text"],
            m["class_name"],
            m["method_name"]
        )
        results.append({
            "class_name": m["class_name"],
            "method_name": m["method_name"],
            "descriptor": m["descriptor"],
            "instruction_count": m["instruction_count"],
            "smali_preview": '\n'.join(m["smali_lines"][:20]),  # first 20 lines for UI
            "smali_full": m["smali_text"],
            "pseudocode": translation.get("pseudocode", ""),
            "threat_summary": translation.get("threat_summary", ""),
            "threat_level": translation.get("threat_level", "unknown"),
            "techniques": translation.get("techniques", [])
        })

    overall_threat = "critical" if any(r["threat_level"] == "critical" for r in results) else \
                     "high" if any(r["threat_level"] == "high" for r in results) else \
                     "medium" if any(r["threat_level"] == "medium" for r in results) else "low"

    return {
        "available": True,
        "method_count": len(results),
        "overall_threat_level": overall_threat,
        "methods": results
    }


if __name__ == "__main__":
    result = run_smali_deobfuscation('/home/pratham/apkguard/samples/meterpreter.apk')
    print(f"Methods found: {result['method_count']}")
    for m in result['methods']:
        print(f"\n{'='*50}")
        print(f"Class: {m['class_name']}")
        print(f"Method: {m['method_name']}")
        print(f"Threat: {m['threat_level'].upper()}")
        print(f"Summary: {m['threat_summary']}")
        print(f"Pseudocode:\n{m['pseudocode'][:300]}")
