import os
import subprocess
import math
from collections import Counter

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    freq = Counter(data)
    for c in freq.values():
        p = c / len(data)
        entropy -= p * math.log2(p)
    return entropy

def extract_strings(file_path):
    result = subprocess.run(
        ["strings", file_path],
        capture_output=True,
        text=True
    )
    return result.stdout.splitlines()[:50]

def extract_features(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    features = {
        "file_name": os.path.basename(file_path),
        "file_extension": os.path.splitext(file_path)[1],
        "file_size": len(data),
        "entropy": round(calculate_entropy(data), 2),
        "suspicious_strings": extract_strings(file_path)
    }
    return features

if __name__ == "__main__":
    artefact = extract_features("/var/www/html/uploads/sample.php")
    print(artefact)
