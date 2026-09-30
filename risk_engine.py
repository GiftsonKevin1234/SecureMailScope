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
            "detail": "Certificate is not signed by a trusted CA. Acceptable for internal/test use, risky for production.",
            "fix": "Obtain a certificate from a trusted Certificate Authority (e.g. Let's Encrypt, DigiCert) instead of self-signing.",
            "compliance": "CA/Browser Forum Baseline Requirements"
        })
        risk_score += 20

    # 2. Expiration check
    now = datetime.now(timezone.utc)
    days_remaining = (cert_obj.not_valid_after_utc - now).days
    if days_remaining < 0:
        findings.append({
            "severity": "CRITICAL",
            "issue": "Certificate expired",
            "detail": f"Expired {abs(days_remaining)} days ago",
            "fix": "Renew the certificate immediately and redeploy it to the mail server. Set up automated renewal (e.g. certbot) to prevent recurrence.",
            "compliance": "NIST SP 800-52 Rev.2"
        })
        risk_score += 50
    elif days_remaining < 30:
        findings.append({
            "severity": "HIGH",
            "issue": "Certificate expiring soon",
            "detail": f"{days_remaining} days remaining",
            "fix": "Schedule certificate renewal now to avoid an unplanned outage or downgrade to an expired-cert state.",
            "compliance": "NIST SP 800-52 Rev.2"
        })
        risk_score += 30

    # 3. Key strength check
    pubkey = cert_obj.public_key()
    if hasattr(pubkey, "key_size"):
        key_size = pubkey.key_size
        if key_size < 2048:
            findings.append({
                "severity": "CRITICAL",
                "issue": "Weak RSA key size",
                "detail": f"{key_size} bits (minimum recommended: 2048)",
                "fix": "Regenerate the private key at a minimum of 2048 bits (4096 preferred) and reissue the certificate.",
                "compliance": "NIST SP 800-131A"
            })
            risk_score += 50
        elif key_size == 2048:
            findings.append({
                "severity": "LOW",
                "issue": "Acceptable key size",
                "detail": f"{key_size} bits (4096 recommended for long-term security)",
                "fix": "No immediate action required. Consider 4096-bit keys for certificates with long validity periods.",
                "compliance": "NIST SP 800-131A"
            })
            risk_score += 5

    # 4. Signature algorithm check
    sig_algo = cert_obj.signature_algorithm_oid._name
    if "sha1" in sig_algo.lower() or "md5" in sig_algo.lower():
        findings.append({
            "severity": "CRITICAL",
            "issue": "Weak signature algorithm",
            "detail": sig_algo,
            "fix": "Reissue the certificate using SHA-256 or stronger as the signature algorithm.",
            "compliance": "NIST SP 800-57"
        })
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
        findings.append({
            "severity": "CRITICAL",
            "issue": "Deprecated TLS version",
            "detail": version_string,
            "fix": "Disable this protocol version in the mail server config (e.g. Dovecot's ssl_min_protocol, Postfix's smtpd_tls_protocols) and require TLS 1.2 or higher.",
            "compliance": "RFC 8996 (deprecates TLS 1.0/1.1)"
        })
        risk_score += 60
    elif version_string == "TLSv1.2":
        findings.append({
            "severity": "LOW",
            "issue": "TLS 1.2 in use",
            "detail": "Acceptable, but TLS 1.3 is preferred",
            "fix": "Enable TLS 1.3 support if the mail server software supports it, for stronger forward secrecy guarantees.",
            "compliance": "RFC 8446"
        })
        risk_score += 5
    elif version_string == "TLSv1.3":
        findings.append({
            "severity": "INFO",
            "issue": "TLS 1.3 in use",
            "detail": "Best practice",
            "fix": "No action required.",
            "compliance": "RFC 8446"
        })

    return {"risk_score": risk_score, "findings": findings}


if __name__ == "__main__":
    import ssl, socket

    def get_cert_and_tls(hostname, port):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.set_ciphers("ALL:@SECLEVEL=0")

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert_obj = x509.load_der_x509_certificate(cert_der)
                tls_version = ssock.version()
        return cert_obj, tls_version

    servers = [
        {"name": "Healthy Server (mail.test.local)", "host": "localhost", "port": 993},
        {"name": "Vulnerable Server (mail-vuln.test.local)", "host": "localhost", "port": 9930},
    ]

    for server in servers:
        print(f"\n{'='*50}")
        print(f"=== SecureMailScope Risk Report: {server['name']} ===")
        print(f"{'='*50}\n")

        cert_obj, tls_version = get_cert_and_tls(server["host"], server["port"])
        cert_result = analyze_certificate(cert_obj)
        tls_result = analyze_tls_version(tls_version)

        total_score = cert_result["risk_score"] + tls_result["risk_score"]
        all_findings = cert_result["findings"] + tls_result["findings"]

        print(f"Overall Risk Score: {total_score}/100+\n")
        print("Findings:")
        for f in all_findings:
            print(f"  [{f['severity']}] {f['issue']}: {f['detail']}")
            print(f"     Fix: {f['fix']}")
            print(f"     Compliance: {f['compliance']}")