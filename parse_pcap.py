import pyshark

pcap_file = "sample_starttls_smtp.pcapng"

TLS_VERSIONS = {
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2 (or TLS 1.3 record layer)",
    "0x0304": "TLS 1.3",
}

CIPHER_SUITES = {
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
    "0x002f": "TLS_RSA_WITH_AES_128_CBC_SHA (weak - no PFS)",
    "0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA (weak - no PFS)",
}

HANDSHAKE_TYPES = {
    "1": "Client Hello",
    "2": "Server Hello",
    "11": "Certificate",
    "12": "Server Key Exchange",
    "14": "Server Hello Done",
    "16": "Client Key Exchange",
}

cap = pyshark.FileCapture(pcap_file, display_filter="tls.handshake")

print(f"Analyzing TLS handshakes in: {pcap_file}\n")

for packet in cap:
    try:
        if hasattr(packet.tls, "handshake_type"):
            htype = packet.tls.handshake_type
            htype_name = HANDSHAKE_TYPES.get(htype, f"Unknown ({htype})")
            print(f"Packet {packet.number}: {htype_name}")

            if hasattr(packet.tls, "handshake_version"):
                ver = packet.tls.handshake_version
                print(f"   Version: {TLS_VERSIONS.get(ver, ver)}")

            if hasattr(packet.tls, "handshake_ciphersuite"):
                cs = packet.tls.handshake_ciphersuite
                print(f"   Cipher Suite: {CIPHER_SUITES.get(cs, cs)}")

            # --- Certificate extraction ---
            if htype == "11":  # Certificate handshake message
                print("   --- Certificate Details ---")
                if hasattr(packet.tls, "x509sat_uTF8String"):
                    print(f"   Subject/Issuer field: {packet.tls.x509sat_uTF8String}")
                if hasattr(packet.tls, "x509af_algorithm_id"):
                    print(f"   Signature Algorithm OID: {packet.tls.x509af_algorithm_id}")
                if hasattr(packet.tls, "x509af_rsaPublicKey_modulus"):
                    modulus = packet.tls.x509af_rsaPublicKey_modulus
                    key_bits = (len(modulus.replace(":", "")) * 4)
                    print(f"   RSA Key Length (approx): {key_bits} bits")
                if hasattr(packet.tls, "x509af_notBefore"):
                    print(f"   Valid From: {packet.tls.x509af_notBefore}")
                if hasattr(packet.tls, "x509af_notAfter"):
                    print(f"   Valid Until: {packet.tls.x509af_notAfter}")

            print()
    except AttributeError:
        continue

cap.close()