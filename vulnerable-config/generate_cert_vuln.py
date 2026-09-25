from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime, os

os.makedirs("mailserver-ssl", exist_ok=True)

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "mail-vuln.test.local"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=400))  # already expired!
    .not_valid_after(datetime.datetime.utcnow() - datetime.timedelta(days=30))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName("mail-vuln.test.local")]), critical=False)
    .sign(key, hashes.SHA256())
)

with open("mailserver-ssl/mail-vuln.test.local-key.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))

with open("mailserver-ssl/mail-vuln.test.local-cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("Vulnerable certificate generated: weak 1024-bit key, SHA1 signature, EXPIRED 30 days ago")