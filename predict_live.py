import joblib
import pandas as pd
from feature_extraction import extract_features

model = joblib.load("isolation_forest_model.pkl")

feature_cols = ["key_size", "days_remaining", "is_expired", "is_self_signed",
                 "tls_version_score", "cipher_bits", "weak_signature"]

servers = [
    {"name": "Healthy Server (mail.test.local)", "host": "localhost", "port": 993},
    {"name": "Vulnerable Server (mail-vuln.test.local)", "host": "localhost", "port": 9930},
]

for server in servers:
    print(f"\n=== {server['name']} ===")
    features = extract_features(server["host"], server["port"])

    X = pd.DataFrame([features])[feature_cols]
    prediction = model.predict(X)[0]
    anomaly_score = model.decision_function(X)[0]  # lower = more anomalous

    label = "ANOMALOUS" if prediction == -1 else "NORMAL"
    print(f"  ML Prediction: {label}")
    print(f"  Anomaly Score: {anomaly_score:.4f} (lower = more anomalous)")
    print(f"  Features: {features}")