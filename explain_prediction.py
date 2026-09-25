import joblib
import pandas as pd
import shap
from feature_extraction import extract_features

model = joblib.load("isolation_forest_model.pkl")

feature_cols = ["key_size", "days_remaining", "is_expired", "is_self_signed",
                 "tls_version_score", "cipher_bits", "weak_signature"]

# Load background data (training set) for SHAP to compare against
df = pd.read_csv("training_data.csv")
X_background = df[feature_cols].sample(50, random_state=42)

explainer = shap.TreeExplainer(model, X_background)

servers = [
    {"name": "Healthy Server", "host": "localhost", "port": 993},
    {"name": "Vulnerable Server", "host": "localhost", "port": 9930},
]

for server in servers:
    print(f"\n{'='*50}")
    print(f"=== {server['name']} ===")
    print(f"{'='*50}")

    features = extract_features(server["host"], server["port"])
    X = pd.DataFrame([features])[feature_cols]

    prediction = model.predict(X)[0]
    label = "ANOMALOUS" if prediction == -1 else "NORMAL"
    print(f"Prediction: {label}\n")

    shap_values = explainer.shap_values(X)

    print("Feature contributions (higher magnitude = more influence on this decision):")
    contributions = list(zip(feature_cols, shap_values[0]))
    contributions.sort(key=lambda x: abs(x[1]), reverse=True)

    for feature, value in contributions:
        direction = "pushed toward ANOMALOUS" if value < 0 else "pushed toward NORMAL"
        print(f"  {feature:20s}: {value:+.4f}  ({direction})")