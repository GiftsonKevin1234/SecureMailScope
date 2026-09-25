import ssl
import socket
from cryptography import x509
from datetime import datetime, timezone

def extract_features(hostname, port):
    """Connect to a mail server and extract a numeric feature vector."""
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
            cipher_name, cipher_proto, cipher_bits = ssock.cipher()

    now = datetime.now(timezone.utc)
    days_remaining = (cert_obj.not_valid_after_utc - now).days
    is_expired = 1 if days_remaining < 0 else 0
    is_self_signed = 1 if cert_obj.subject == cert_obj.issuer else 0

    pubkey = cert_obj.public_key()
    key_size = pubkey.key_size if hasattr(pubkey, "key_size") else 0

    tls_version_score = {
        "SSLv3": 0, "TLSv1": 1, "TLSv1.1": 2, "TLSv1.2": 3, "TLSv1.3": 4
    }.get(tls_version, -1)

    sig_algo = cert_obj.signature_algorithm_oid._name
    weak_signature = 1 if ("sha1" in sig_algo.lower() or "md5" in sig_algo.lower()) else 0

    features = {
        "key_size": key_size,
        "days_remaining": days_remaining,
        "is_expired": is_expired,
        "is_self_signed": is_self_signed,
        "tls_version_score": tls_version_score,
        "cipher_bits": cipher_bits,
        "weak_signature": weak_signature,
    }
    return features


if __name__ == "__main__":
    servers = [
        {"name": "Healthy", "host": "localhost", "port": 993},
        {"name": "Vulnerable", "host": "localhost", "port": 9930},
    ]

    for server in servers:
        print(f"\n--- {server['name']} ---")
        features = extract_features(server["host"], server["port"])
        for k, v in features.items():
            print(f"  {k}: {v}")