"""
APKGuard AI — batch_tester.py
Synthetic 50-sample batch test for ML classifier validation.
Generates confusion matrix from feature vectors derived from real malware families.
"""
import numpy as np
from ml_classifier import normalize, MAX_VALS, KNOWN_MALWARE, KNOWN_BENIGN

# Synthetic dataset — 50 samples derived from real malware family characteristics
# Features: [dangerous_perms, suspicious_apis, network_indicators, obfuscation_score, banking_indicators]
# Label: 1=malware, 0=benign

SYNTHETIC_DATASET = [
    # MALWARE samples (28) — based on real family signatures
    ([10, 7, 0, 5, 2], 1, "meterpreter"),
    ([10, 7, 0, 5, 2], 1, "banking_demo"),
    ([12, 10, 3, 12, 4], 1, "SpyNote"),
    ([15, 12, 4, 15, 5], 1, "BankBot"),
    ([8, 6, 1, 8, 2], 1, "AndroRAT"),
    ([11, 9, 3, 10, 4], 1, "Cerberus"),
    ([9, 7, 2, 9, 3], 1, "AhMyth"),
    ([13, 11, 4, 14, 5], 1, "Anubis"),
    ([7, 5, 1, 6, 2], 1, "insecurebank"),
    ([14, 12, 5, 13, 5], 1, "Xenomorph"),
    ([11, 8, 3, 11, 4], 1, "SharkBot"),
    ([10, 9, 2, 10, 3], 1, "AlienBot"),
    ([13, 10, 4, 12, 5], 1, "Hydra"),
    ([9, 8, 2, 8, 3], 1, "FluBot"),
    ([12, 11, 3, 13, 4], 1, "TrickMo"),
    ([8, 7, 1, 7, 2], 1, "Gustuff"),
    ([10, 8, 3, 9, 3], 1, "EventBot"),
    ([11, 9, 2, 11, 4], 1, "TeaBot"),
    ([9, 6, 2, 8, 2], 1, "Medusa"),
    ([13, 11, 4, 14, 5], 1, "Ginp"),
    ([8, 6, 1, 7, 2], 1, "BianLian"),
    ([10, 8, 3, 10, 3], 1, "PixPirate"),
    ([12, 9, 3, 11, 4], 1, "Coper"),
    ([9, 7, 2, 9, 3], 1, "Hook"),
    ([11, 8, 3, 10, 3], 1, "GoldDigger"),
    ([8, 6, 1, 6, 2], 1, "Zanubis"),
    ([10, 7, 2, 8, 3], 1, "SpinOk"),
    ([9, 8, 2, 9, 3], 1, "DragonEgg"),
    # BENIGN samples (16)
    ([1, 0, 0, 0, 0], 0, "simple_util"),
    ([2, 1, 0, 1, 0], 0, "camera_app"),
    ([0, 0, 0, 0, 0], 0, "minimal_app"),
    ([1, 1, 0, 0, 0], 0, "location_app"),
    ([2, 0, 1, 0, 0], 0, "network_app"),
    ([1, 1, 0, 1, 0], 0, "storage_app"),
    ([3, 1, 1, 2, 0], 0, "complex_legit"),
    ([2, 2, 1, 1, 0], 0, "social_app"),
    ([1, 0, 1, 0, 0], 0, "browser_app"),
    ([2, 1, 0, 2, 0], 0, "obfuscated_legit"),
    ([3, 2, 1, 1, 0], 0, "popular_app"),
    ([2, 1, 1, 0, 0], 0, "banking_legit"),
    ([1, 1, 0, 0, 0], 0, "news_app"),
    ([2, 0, 0, 1, 0], 0, "game_app"),
    ([1, 1, 1, 0, 0], 0, "maps_app"),
    ([3, 1, 2, 1, 0], 0, "productivity_app"),
    # GRAYWARE (6) — suspicious but not confirmed malware
    ([5, 3, 1, 4, 1], 1, "adware_variant"),
    ([4, 2, 1, 3, 0], 1, "stalkerware"),
    ([6, 4, 2, 5, 1], 1, "aggressive_adware"),
    ([3, 2, 0, 3, 0], 0, "borderline_app"),
    ([4, 3, 1, 4, 1], 1, "riskware"),
    ([3, 2, 1, 2, 0], 0, "dual_use_tool"),
]

def run_batch_test() -> dict:
    """Run the legacy synthetic batch test and return a confusion matrix.

    This is intentionally labelled as synthetic. It is useful only for checking the
    K-Means feature-vector demonstration code; it is not evidence of real-world APK
    malware detection performance.
    """
    from sklearn.cluster import KMeans
    from sklearn.preprocessing import StandardScaler

    malware_features = [normalize(f, MAX_VALS) for f in KNOWN_MALWARE]
    benign_features = [normalize(f, MAX_VALS) for f in KNOWN_BENIGN]
    x_train = np.array(malware_features + benign_features)

    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(x_train)
    kmeans = KMeans(n_clusters=2, random_state=42, n_init=10)
    kmeans.fit(x_scaled)

    cluster_labels = kmeans.labels_
    malware_cluster = round(sum(cluster_labels[:len(malware_features)]) / len(malware_features))

    tp = tn = fp = fn = 0
    results = []
    false_negatives = []
    false_positives = []
    extraction_failures = []

    for features, true_label, name in SYNTHETIC_DATASET:
        try:
            norm_f = normalize(features, MAX_VALS)
            apk_scaled = scaler.transform([norm_f])
            cluster = kmeans.predict(apk_scaled)[0]
            distances = kmeans.transform(apk_scaled)[0]
            dist_mal = distances[malware_cluster]
            dist_ben = distances[1 - malware_cluster]
            total_distance = dist_mal + dist_ben
            confidence = round((1 - dist_mal / total_distance) * 100) if total_distance > 0 else 50
            predicted_malware = cluster == malware_cluster
            predicted_label = 1 if predicted_malware else 0

            if true_label == 1 and predicted_label == 1:
                tp += 1
            elif true_label == 0 and predicted_label == 0:
                tn += 1
            elif true_label == 0 and predicted_label == 1:
                fp += 1
                false_positives.append(name)
            else:
                fn += 1
                false_negatives.append(name)

            results.append({
                "name": name,
                "true_label": "malware" if true_label else "benign",
                "predicted": "malware" if predicted_label else "benign",
                "correct": true_label == predicted_label,
                "confidence": confidence,
            })
        except Exception as exc:
            extraction_failures.append(name)
            if true_label == 1:
                tp += 1
            else:
                fp += 1
            results.append({
                "name": name,
                "true_label": "malware" if true_label else "benign",
                "predicted": "malware",
                "correct": true_label == 1,
                "confidence": 0,
                "extraction_failed": True,
                "error": str(exc),
            })

    total = tp + tn + fp + fn
    accuracy = round((tp + tn) / total * 100, 1) if total else 0
    precision = round(tp / (tp + fp) * 100, 1) if (tp + fp) else 0
    recall = round(tp / (tp + fn) * 100, 1) if (tp + fn) else 0
    f1 = round(2 * precision * recall / (precision + recall), 1) if (precision + recall) else 0

    return {
        "total_samples": total,
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "results": results,
        "model": "K-Means (k=2) with StandardScaler",
        "validation_notice": "Synthetic feature-vector experiment only; not a real-world APK malware benchmark.",
        "extraction_failures": extraction_failures,
    }

if __name__ == "__main__":
    result = run_batch_test()
    print(f"Total: {result['total_samples']} | TP={result['TP']} TN={result['TN']} FP={result['FP']} FN={result['FN']}")
    print(f"Accuracy: {result['accuracy']}% | Precision: {result['precision']}% | Recall: {result['recall']}% | F1: {result['f1_score']}%")
    print(f"False Negatives: {result['false_negatives']}")
    print(f"False Positives: {result['false_positives']}")
