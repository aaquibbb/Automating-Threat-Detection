import re
import json
from collections import Counter

SQL_PATTERNS = [
    r"(\bor\b|\band\b)\s+\d=\d",
    r"union\s+select",
    r"sleep\(",
    r"benchmark\("
]

XSS_PATTERNS = [
    r"<script>",
    r"onerror=",
    r"alert\(",
    r"%3Cscript"
]

def detect_indicators(uri):
    indicators = []
    for p in SQL_PATTERNS:
        if re.search(p, uri, re.IGNORECASE):
            indicators.append("SQL_INJECTION_PATTERN")
    for p in XSS_PATTERNS:
        if re.search(p, uri, re.IGNORECASE):
            indicators.append("XSS_PATTERN")
    return indicators

def summarize_log(log_line):
    log_regex = r'\"(GET|POST|PUT|DELETE) (.*?) HTTP.*\" (\d{3}).*\"(.*?)\"$'
    match = re.search(log_regex, log_line)

    if not match:
        return None

    method, uri, status, user_agent = match.groups()

    indicators = detect_indicators(uri)

    summary = {
        "request_method": method,
        "request_uri": uri.split("?")[0],
        "parameters": uri.split("?")[1] if "?" in uri else None,
        "status_code": int(status),
        "user_agent": user_agent,
        "attack_indicators": indicators
    }
    return summary

def process_log_file(logfile):
    summaries = []
    with open(logfile, "r") as f:
        for line in f:
            s = summarize_log(line)
            if s:
                summaries.append(s)
    return summaries

if __name__ == "__main__":
    summaries = process_log_file("/var/log/nginx/access.log")
    print(json.dumps(summaries[:5], indent=2))
