import ssl
import socket
from datetime import datetime

hostname = "localhost"
port = 993  # IMAPS - encrypted from the start, good for direct cert check

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

with socket.create_connection((hostname, port)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        cert = ssock.getpeercert(binary_form=True)
        cert_dict = ssock.getpeercert()
        print("TLS Version negotiated:", ssock.version())
        print("Cipher used:", ssock.cipher())

        # Decode cert with cryptography library for full details
        from cryptography import x509
        cert_obj = x509.load_der_x509_certificate(cert)
        print("\n--- Certificate Details ---")
        print("Subject:", cert_obj.subject)
        print("Issuer:", cert_obj.issuer)
        print("Valid From:", cert_obj.not_valid_before_utc)
        print("Valid Until:", cert_obj.not_valid_after_utc)
        print("Serial Number:", cert_obj.serial_number)
        pubkey = cert_obj.public_key()
        print("Public Key Type:", type(pubkey).__name__)
        if hasattr(pubkey, "key_size"):
            print("Key Size:", pubkey.key_size, "bits")