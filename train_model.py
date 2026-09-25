import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
import joblib

# Load data
df = pd.read_csv("training_data.csv")

feature_cols = ["key_size", "days_remaining", "is_expired", "is_self_signed",
                 "tls_version_score", "cipher_bits", "weak_signature"]

X = df[feature_cols]
y_true = df["label"]  # only used for evaluation, NOT for training (unsupervised)

# Split for evaluation later
X_train, X_test, y_train, y_test = train_test_split(X, y_true, test_size=0.2, random_state=42)

# Train Isolation Forest (unsupervised anomaly detection)
# contamination = expected proportion of anomalies in the data
model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
model.fit(X_train)

# Save the trained model for reuse
joblib.dump(model, "isolation_forest_model.pkl")
print("Model trained and saved to isolation_forest_model.pkl\n")

# Evaluate on test set
predictions = model.predict(X_test)  # returns 1 (normal) or -1 (anomaly)
predicted_labels = ["anomalous" if p == -1 else "normal" for p in predictions]

correct = sum(1 for pred, actual in zip(predicted_labels, y_test) if pred == actual)
accuracy = correct / len(y_test)

print(f"Test set size: {len(y_test)}")
print(f"Correct predictions: {correct}")
print(f"Accuracy: {accuracy:.2%}\n")

print("Sample predictions vs actual:")
for i, (pred, actual) in enumerate(zip(predicted_labels, y_test)):
    marker = "✓" if pred == actual else "✗"
    print(f"  {marker} Predicted: {pred:12s} | Actual: {actual}")