import ssl
import socket
from cryptography import x509

hostname = "localhost"
port = 9930  # IMAPS port for the vulnerable server

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.minimum_version = ssl.TLSVersion.TLSv1  # allow old TLS for this vulnerability test
context.set_ciphers("ALL:@SECLEVEL=0")  # allow weak/legacy ciphers for testing

with socket.create_connection((hostname, port)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        cert = ssock.getpeercert(binary_form=True)
        print("TLS Version negotiated:", ssock.version())
        print("Cipher used:", ssock.cipher())

        cert_obj = x509.load_der_x509_certificate(cert)
        print("\n--- Certificate Details ---")
        print("Subject:", cert_obj.subject)
        print("Valid From:", cert_obj.not_valid_before_utc)
        print("Valid Until:", cert_obj.not_valid_after_utc)
        pubkey = cert_obj.public_key()
        if hasattr(pubkey, "key_size"):
            print("Key Size:", pubkey.key_size, "bits")