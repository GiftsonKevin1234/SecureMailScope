import random
import csv

def generate_normal_sample():
    """Simulate a healthy, well-configured mail server session."""
    return {
        "key_size": random.choice([2048, 2048, 2048, 4096]),
        "days_remaining": random.randint(60, 365),
        "is_expired": 0,
        "is_self_signed": random.choice([0, 0, 1]),  # mostly CA-signed in a "normal" population
        "tls_version_score": random.choice([3, 4, 4, 4]),  # mostly TLS 1.3, some 1.2
        "cipher_bits": random.choice([128, 256, 256]),
        "weak_signature": 0,
    }

def generate_anomalous_sample():
    """Simulate a vulnerable/misconfigured session."""
    anomaly_type = random.choice(["expired", "weak_key", "old_tls", "weak_sig", "combo"])

    sample = {
        "key_size": 2048,
        "days_remaining": random.randint(30, 200),
        "is_expired": 0,
        "is_self_signed": 1,
        "tls_version_score": 4,
        "cipher_bits": 256,
        "weak_signature": 0,
    }

    if anomaly_type == "expired":
        sample["days_remaining"] = random.randint(-200, -1)
        sample["is_expired"] = 1
    elif anomaly_type == "weak_key":
        sample["key_size"] = random.choice([512, 1024])
    elif anomaly_type == "old_tls":
        sample["tls_version_score"] = random.choice([0, 1, 2])
        sample["cipher_bits"] = random.choice([40, 56, 112])
    elif anomaly_type == "weak_sig":
        sample["weak_signature"] = 1
    elif anomaly_type == "combo":
        sample["days_remaining"] = random.randint(-100, -1)
        sample["is_expired"] = 1
        sample["key_size"] = 1024
        sample["tls_version_score"] = random.choice([0, 1])

    return sample


if __name__ == "__main__":
    rows = []

    # 150 normal samples, 30 anomalous (realistic-ish ratio for demo purposes)
    for _ in range(150):
        row = generate_normal_sample()
        row["label"] = "normal"
        rows.append(row)

    for _ in range(30):
        row = generate_anomalous_sample()
        row["label"] = "anomalous"
        rows.append(row)

    random.shuffle(rows)

    fieldnames = ["key_size", "days_remaining", "is_expired", "is_self_signed",
                  "tls_version_score", "cipher_bits", "weak_signature", "label"]

    with open("training_data.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {len(rows)} samples -> training_data.csv")
    print(f"  Normal: 150, Anomalous: 30")