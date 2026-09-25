from cryptography import x509
from datetime import datetime, timezone

def analyze_certificate(cert_obj):
    """Analyze an X.509 certificate and return risk findings."""
    findings = []
    risk_score = 0

    # 1. Self-signed check
    if cert_obj.subject == cert_obj.issuer:
        findings.append({
            "severity": "MEDIUM",
            "issue": "Self-signed certificate",
            "detail": "Certificate is not signed by a trusted CA. Acceptable for internal/test use, risky for production."
        })
        risk_score += 20

    # 2. Expiration check
    now = datetime.now(timezone.utc)
    days_remaining = (cert_obj.not_valid_after_utc - now).days
    if days_remaining < 0:
        findings.append({"severity": "CRITICAL", "issue": "Certificate expired", "detail": f"Expired {abs(days_remaining)} days ago"})
        risk_score += 50
    elif days_remaining < 30:
        findings.append({"severity": "HIGH", "issue": "Certificate expiring soon", "detail": f"{days_remaining} days remaining"})
        risk_score += 30

    # 3. Key strength check
    pubkey = cert_obj.public_key()
    if hasattr(pubkey, "key_size"):
        key_size = pubkey.key_size
        if key_size < 2048:
            findings.append({"severity": "CRITICAL", "issue": "Weak RSA key size", "detail": f"{key_size} bits (minimum recommended: 2048)"})
            risk_score += 50
        elif key_size == 2048:
            findings.append({"severity": "LOW", "issue": "Acceptable key size", "detail": f"{key_size} bits (4096 recommended for long-term security)"})
            risk_score += 5

    # 4. Signature algorithm check
    sig_algo = cert_obj.signature_algorithm_oid._name
    if "sha1" in sig_algo.lower() or "md5" in sig_algo.lower():
        findings.append({"severity": "CRITICAL", "issue": "Weak signature algorithm", "detail": sig_algo})
        risk_score += 50

    return {
        "risk_score": min(risk_score, 100),
        "findings": findings
    }


def analyze_tls_version(version_string):
    """Flag deprecated TLS versions."""
    findings = []
    risk_score = 0

    if version_string in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
        findings.append({"severity": "CRITICAL", "issue": "Deprecated TLS version", "detail": version_string})
        risk_score += 60
    elif version_string == "TLSv1.2":
        findings.append({"severity": "LOW", "issue": "TLS 1.2 in use", "detail": "Acceptable, but TLS 1.3 is preferred"})
        risk_score += 5
    elif version_string == "TLSv1.3":
        findings.append({"severity": "INFO", "issue": "TLS 1.3 in use", "detail": "Best practice"})

    return {"risk_score": risk_score, "findings": findings}


if __name__ == "__main__":
    # Quick test using check_cert.py's logic
    import ssl, socket

    hostname = "localhost"
    port = 993

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            cert_obj = x509.load_der_x509_certificate(cert_der)
            tls_version = ssock.version()

    cert_result = analyze_certificate(cert_obj)
    tls_result = analyze_tls_version(tls_version)

    total_score = cert_result["risk_score"] + tls_result["risk_score"]
    all_findings = cert_result["findings"] + tls_result["findings"]

    print(f"=== SecureMailScope Risk Report ===\n")
    print(f"Overall Risk Score: {total_score}/100+\n")
    print("Findings:")
    for f in all_findings:
        print(f"  [{f['severity']}] {f['issue']}: {f['detail']}")