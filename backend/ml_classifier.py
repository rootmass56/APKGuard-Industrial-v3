"""
APKGuard AI — ml_classifier.py
K-Means clustering for APK malware classification.
Uses mutually exclusive features from static analysis only.
"""
import numpy as np
import json
import os
from pathlib import Path

MODEL_FILE = Path(os.path.expanduser("~/apkguard/backend/kmeans_model.json"))

# Known APK profiles for initial training
# Features: [dangerous_perms, suspicious_apis, network_indicators, obfuscation_score, banking_indicators]
KNOWN_MALWARE = [
    [10, 7, 0, 5, 2],   # meterpreter.apk (simple RAT stager)
    [10, 7, 0, 5, 2],   # banking_demo.apk (meterpreter variant)
    [12, 10, 3, 12, 4], # SpyNote variant
    [15, 12, 4, 15, 5], # BankBot variant
    [8, 6, 1, 8, 2],    # AndroRAT variant
    [11, 9, 3, 10, 4],  # Cerberus variant
    [9, 7, 2, 9, 3],    # AhMyth variant
    [13, 11, 4, 14, 5], # Anubis variant
    [8, 5, 1, 5, 2],    # Simple SMS stealer
    [9, 6, 2, 8, 3],    # Location tracker
    [10, 8, 3, 10, 4],  # Banking trojan
    [7, 5, 1, 6, 2],    # insecurebank.apk
]

KNOWN_BENIGN = [
    [1, 0, 0, 0, 0],   # Simple utility app
    [2, 1, 0, 1, 0],   # Basic app with camera
    [0, 0, 0, 0, 0],   # Minimal app
    [1, 1, 0, 0, 0],   # App with location
    [2, 0, 1, 0, 0],   # App with network
    [1, 1, 0, 1, 0],   # App with storage
    [3, 1, 1, 2, 0],   # Complex legitimate app
    [2, 2, 1, 1, 0],   # App with multiple features
    [1, 0, 1, 0, 0],   # Network app
    [2, 1, 0, 2, 0],   # App with obfuscation (legit)
    [3, 2, 1, 1, 0],   # Popular social app
    [2, 1, 1, 0, 0],   # Banking app (legit)
]

def extract_features(analysis: dict) -> list:
    """Extract numerical feature vector from static analysis."""
    # Feature 1: Dangerous permissions count
    dangerous_perms = len(analysis.get("permissions", {}).get("dangerous", []))
    
    # Feature 2: Suspicious APIs (fallback to permission-based inference if empty)
    suspicious_apis = len(analysis.get("suspicious_apis", []))
    if suspicious_apis == 0:
        # Infer from dangerous permissions as proxy
        dangerous_list = [p.get("permission","") for p in analysis.get("permissions",{}).get("dangerous",[])]
        dangerous_str = " ".join(dangerous_list)
        if "READ_SMS" in dangerous_str or "SEND_SMS" in dangerous_str:
            suspicious_apis += 3
        if "RECORD_AUDIO" in dangerous_str or "CAMERA" in dangerous_str:
            suspicious_apis += 2
        if "READ_CONTACTS" in dangerous_str or "READ_CALL_LOG" in dangerous_str:
            suspicious_apis += 2
        if "ACCESS_FINE_LOCATION" in dangerous_str:
            suspicious_apis += 1

    # Feature 3: Network indicators
    urls = len(analysis.get("urls_ips", {}).get("urls", []))
    ips = len(analysis.get("urls_ips", {}).get("ips", []))
    network_indicators = urls + ips
    # Add network permission as proxy
    all_perms = " ".join([p.get("permission","") for p in analysis.get("permissions",{}).get("dangerous",[])])
    if "INTERNET" in analysis.get("permissions",{}).get("all",[]):
        network_indicators = max(network_indicators, 1)

    # Feature 4: Obfuscation score
    obfuscation_score = analysis.get("obfuscation", {}).get("score", 0)
    
    # Feature 5: Banking/malware indicators
    banking_indicators = len(analysis.get("banking_indicators", []))
    # Infer from permission combinations
    if "READ_SMS" in all_perms and "SEND_SMS" in all_perms:
        banking_indicators = max(banking_indicators, 2)
    if "RECEIVE_SMS" in all_perms and "READ_CONTACTS" in all_perms:
        banking_indicators = max(banking_indicators, 1)

    return [dangerous_perms, suspicious_apis, network_indicators, obfuscation_score, banking_indicators]

def normalize(features: list, max_vals: list) -> list:
    """Normalize features to 0-1 range."""
    return [f/m if m > 0 else 0 for f, m in zip(features, max_vals)]

MAX_VALS = [20, 20, 10, 20, 10]  # Max expected values per feature

def kmeans_classify(analysis: dict) -> dict:
    """
    Classify APK using K-Means clustering.
    Returns cluster assignment, distance to malware/benign centroids,
    and confidence score.
    """
    from sklearn.cluster import KMeans
    from sklearn.preprocessing import StandardScaler

    # Build training data
    malware_features = [normalize(f, MAX_VALS) for f in KNOWN_MALWARE]
    benign_features = [normalize(f, MAX_VALS) for f in KNOWN_BENIGN]
    
    X = np.array(malware_features + benign_features)

    # Train K-Means with 2 clusters
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    kmeans = KMeans(n_clusters=2, random_state=42, n_init=10)
    kmeans.fit(X_scaled)

    # Determine which cluster is malware
    cluster_labels = kmeans.labels_
    malware_cluster = round(sum(cluster_labels[:len(malware_features)]) / len(malware_features))

    # Extract and classify new APK
    raw_features = extract_features(analysis)
    norm_features = normalize(raw_features, MAX_VALS)
    apk_scaled = scaler.transform([norm_features])
    
    cluster = kmeans.predict(apk_scaled)[0]
    
    # Calculate distances to both centroids
    distances = kmeans.transform(apk_scaled)[0]
    dist_to_malware = distances[malware_cluster]
    dist_to_benign = distances[1 - malware_cluster]
    
    # Confidence = how much closer to malware cluster vs benign
    total_dist = dist_to_malware + dist_to_benign
    malware_confidence = round((1 - dist_to_malware/total_dist) * 100) if total_dist > 0 else 50
    
    is_malware_cluster = (cluster == malware_cluster)
    
    # Final classification
    if is_malware_cluster and malware_confidence >= 70:
        classification = "MALICIOUS"
        risk_contribution = min(malware_confidence // 3, 20)
    elif is_malware_cluster and malware_confidence >= 50:
        classification = "SUSPICIOUS"
        risk_contribution = min(malware_confidence // 5, 10)
    else:
        classification = "BENIGN"
        risk_contribution = 0

    return {
        "ml_classification": classification,
        "ml_confidence": malware_confidence,
        "ml_cluster": int(cluster),
        "malware_cluster_id": int(malware_cluster),
        "dist_to_malware": round(dist_to_malware, 3),
        "dist_to_benign": round(dist_to_benign, 3),
        "features_used": {
            "dangerous_permissions": raw_features[0],
            "suspicious_apis": raw_features[1],
            "network_indicators": raw_features[2],
            "obfuscation_score": raw_features[3],
            "banking_indicators": raw_features[4]
        },
        "risk_contribution": risk_contribution,
        "model": "K-Means (k=2)",
        "training_samples": f"{len(malware_features)} malware + {len(benign_features)} benign"
    }

if __name__ == "__main__":
    # Test
    test_analysis = {
        "permissions": {"dangerous": [{}]*10},
        "suspicious_apis": [{}]*8,
        "urls_ips": {"urls": ["http://evil.com"], "ips": ["1.2.3.4"]},
        "obfuscation": {"score": 10},
        "banking_indicators": ["overlay", "sms_intercept"]
    }
    result = kmeans_classify(test_analysis)
    import json
    print(json.dumps(result, indent=2))
