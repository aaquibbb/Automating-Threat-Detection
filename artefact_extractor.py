import os
import subprocess
import math
from collections import Counter

SUSPICIOUS_KEYWORDS = [
    "base64_decode",
    "eval",
    "strrev",
    "proc_open",
    "pcntl_fork",
    "posix_setsid",
    "/bin/sh",
    "fsockopen",
    "stream_select"
]

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
        text=True,
        errors="ignore"
    )
    raw_strings = result.stdout.splitlines()

    indicators = set()
    for s in raw_strings:
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in s:
                indicators.add(kw)

    return list(indicators)

def extract_features(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    features = {
        "file_extension": os.path.splitext(file_path)[1],
        "file_size": len(data),
        "entropy": round(calculate_entropy(data), 2),
        "indicators": extract_strings(file_path),
        "execution_context": "web_upload_directory"
    }
    return features


if __name__ == "__main__":
    artefact = extract_features("/reverse_shell.php")
    print(artefact)
