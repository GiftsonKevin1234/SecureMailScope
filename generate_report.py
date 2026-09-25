import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from feature_extraction import extract_features
from risk_engine import analyze_certificate, analyze_tls_version
import joblib
import pandas as pd
import shap
import ssl, socket
from cryptography import x509


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


def full_analysis(host, port):
    model = joblib.load("isolation_forest_model.pkl")
    feature_cols = ["key_size", "days_remaining", "is_expired", "is_self_signed",
                     "tls_version_score", "cipher_bits", "weak_signature"]

    df = pd.read_csv("training_data.csv")
    X_background = df[feature_cols].sample(50, random_state=42)
    explainer = shap.TreeExplainer(model, X_background)

    features = extract_features(host, port)
    X = pd.DataFrame([features])[feature_cols]

    prediction = model.predict(X)[0]
    anomaly_score = float(model.decision_function(X)[0])
    ml_label = "ANOMALOUS" if prediction == -1 else "NORMAL"

    shap_values = explainer.shap_values(X)
    contributions = sorted(
        zip(feature_cols, shap_values[0].tolist()),
        key=lambda x: abs(x[1]), reverse=True
    )

    cert_obj, tls_version = get_cert_and_tls(host, port)
    cert_result = analyze_certificate(cert_obj)
    tls_result = analyze_tls_version(tls_version)
    rule_score = min(cert_result["risk_score"] + tls_result["risk_score"], 100)
    findings = cert_result["findings"] + tls_result["findings"]

    return {
        "host": host,
        "port": port,
        "timestamp": datetime.now().isoformat(),
        "features": features,
        "ml_prediction": ml_label,
        "ml_anomaly_score": round(anomaly_score, 4),
        "shap_explanation": [{"feature": f, "impact": round(v, 4)} for f, v in contributions],
        "rule_based_risk_score": rule_score,
        "findings": findings,
    }


def export_json(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"JSON report saved: {filename}")


def export_pdf(data, filename):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle("Title", parent=styles["Heading1"], textColor=colors.HexColor("#1a1a2e"))
    elements.append(Paragraph("SecureMailScope — Security Posture Report", title_style))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Target: {data['host']}:{data['port']}", styles["Normal"]))
    elements.append(Paragraph(f"Generated: {data['timestamp']}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    risk_color = colors.red if data["rule_based_risk_score"] >= 60 else (
        colors.orange if data["rule_based_risk_score"] >= 30 else colors.green)
    risk_style = ParagraphStyle("Risk", parent=styles["Heading2"], textColor=risk_color)
    elements.append(Paragraph(f"Risk Score: {data['rule_based_risk_score']}/100", risk_style))
    elements.append(Paragraph(f"ML Verdict: {data['ml_prediction']} (score: {data['ml_anomaly_score']})", styles["Normal"]))
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Findings", styles["Heading2"]))
    findings_data = [["Severity", "Issue", "Detail"]]
    for f in data["findings"]:
        findings_data.append([f["severity"], f["issue"], f["detail"]])

    findings_table = Table(findings_data, colWidths=[80, 150, 260])
    findings_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(findings_table)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Top ML Feature Contributions (SHAP)", styles["Heading2"]))
    shap_data = [["Feature", "Impact", "Direction"]]
    for s in data["shap_explanation"]:
        direction = "toward anomalous" if s["impact"] < 0 else "toward normal"
        shap_data.append([s["feature"], str(s["impact"]), direction])

    shap_table = Table(shap_data, colWidths=[150, 100, 240])
    shap_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    elements.append(shap_table)

    doc.build(elements)
    print(f"PDF report saved: {filename}")


if __name__ == "__main__":
    servers = [
        {"name": "healthy", "host": "localhost", "port": 993},
        {"name": "vulnerable", "host": "localhost", "port": 9930},
    ]

    for server in servers:
        data = full_analysis(server["host"], server["port"])
        export_json(data, f"report_{server['name']}.json")
        export_pdf(data, f"report_{server['name']}.pdf")