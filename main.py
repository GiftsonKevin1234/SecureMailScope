from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import joblib
import pandas as pd
import shap

from feature_extraction import extract_features
from risk_engine import analyze_certificate, analyze_tls_version
from generate_report import full_analysis, export_json, export_pdf
import ssl, socket
from cryptography import x509

app = FastAPI(title="SecureMailScope API")

# Allow your future dashboard (running in a browser) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

model = joblib.load("isolation_forest_model.pkl")
feature_cols = ["key_size", "days_remaining", "is_expired", "is_self_signed",
                 "tls_version_score", "cipher_bits", "weak_signature"]

df = pd.read_csv("training_data.csv")
X_background = df[feature_cols].sample(50, random_state=42)
explainer = shap.TreeExplainer(model, X_background)


def get_cert_and_tls(hostname, port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1
    context.set_ciphers("ALL:@SECLEVEL=0")

    with socket.create_connection((hostname, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            cert_obj = x509.load_der_x509_certificate(cert_der)
            tls_version = ssock.version()
    return cert_obj, tls_version


@app.get("/")
def root():
    return {"message": "SecureMailScope API is running"}


@app.get("/analyze")
def analyze(host: str = "localhost", port: int = 993):
    try:
        # 1. Extract features
        features = extract_features(host, port)
        X = pd.DataFrame([features])[feature_cols]

        # 2. ML prediction
        prediction = model.predict(X)[0]
        anomaly_score = float(model.decision_function(X)[0])
        ml_label = "ANOMALOUS" if prediction == -1 else "NORMAL"

        # 3. SHAP explanation
        shap_values = explainer.shap_values(X)
        contributions = sorted(
            zip(feature_cols, shap_values[0].tolist()),
            key=lambda x: abs(x[1]), reverse=True
        )
        explanation = [
            {"feature": f, "impact": round(v, 4),
             "direction": "toward anomalous" if v < 0 else "toward normal"}
            for f, v in contributions
        ]

        # 4. Rule-based findings
        cert_obj, tls_version = get_cert_and_tls(host, port)
        cert_result = analyze_certificate(cert_obj)
        tls_result = analyze_tls_version(tls_version)
        rule_score = cert_result["risk_score"] + tls_result["risk_score"]
        findings = cert_result["findings"] + tls_result["findings"]

        return {
            "host": host,
            "port": port,
            "features": features,
            "ml_prediction": ml_label,
            "ml_anomaly_score": round(anomaly_score, 4),
            "shap_explanation": explanation,
            "rule_based_risk_score": min(rule_score, 100),
            "findings": findings,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/report/pdf")
def report_pdf(host: str = "localhost", port: int = 993):
    try:
        data = full_analysis(host, port)
        filename = f"report_{host}_{port}.pdf"
        export_pdf(data, filename)
        return FileResponse(filename, media_type="application/pdf", filename=filename)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/report/json")
def report_json(host: str = "localhost", port: int = 993):
    try:
        data = full_analysis(host, port)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))