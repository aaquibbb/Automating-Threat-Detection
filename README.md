# Automating Threat Detection & YARA Rule Generation with LLMs

**Can a Large Language Model write detection rules good enough to deploy in a SOC?** This project builds an end-to-end pipeline that uses Google Gemini to automatically generate, validate, and deploy YARA rules into Wazuh (open-source SIEM) — then tests them honestly against 480 real-world malicious web shells.

> MSc Cybersecurity dissertation, Northumbria University (2026): *"Automating Threat Detection and YARA Rule Generation Using Large Language Models (LLM) for Wazuh in Web Server Environments."*

![Python](https://img.shields.io/badge/Python-3.x-blue)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh-orange)
![LLM](https://img.shields.io/badge/LLM-Google%20Gemini-green)
![Detection](https://img.shields.io/badge/Rules-YARA-red)

---

## The Problem

Writing YARA rules by hand to catch malicious file uploads (web shells) is slow and reactive. Signature-based detection is always one payload behind, and manual rule maintenance is an operational bottleneck that fuels analyst alert fatigue. The question this project answers: **can an LLM take over the grunt work of rule generation — and are the rules it produces actually deployable?**

## Results

Rules were evaluated against a positive set of **480 real malicious PHP web shells** (c99, r57, obfuscated backdoors from the Tennc Webshell Corpus and SecLists) and a negative set of clean **WordPress, Joomla, and Drupal** source code (to measure false positives).

| Metric | Score |
|---|---|
| Precision | **0.936** |
| F1-Score | **0.89** |
| False Positive Rate | Low enough for operational deployment |

**The honest finding:** the LLM-generated static rules performed strongly on known and lightly-modified web shells, but **heavily obfuscated malware slipped past**. Static YARA detection has a ceiling, and an LLM writing static rules inherits it. The conclusion isn't "AI replaces detection engineers" — it's that LLM-assisted rule generation is a strong *first layer* in a defence-in-depth stack, not a standalone solution.

## How It Works

```
Web server artefact (suspect PHP file)
        │
        ▼
[artifact_extractor.py]   → extract entropy, metadata, strings
        │
        ▼
[rule_generator.py]       → Gemini generates a candidate YARA rule
        │                    (prompt-engineered for valid metadata/strings/conditions)
        ▼
[rule_validator.py]       → compile + test against malicious & benign sets
        │
        ├── passes ──────► deploy rule into Wazuh
        └── fails ───────► feedback loop: regenerate with refined prompt
```

Feature extraction is deterministic and happens *before* any model interaction, keeping a clear separation between AI-assisted output and human-validated production content.

## Technology Stack

- **Detection platform:** Wazuh (file integrity monitoring + alert pipeline)
- **Monitored environment:** Apache web server, PHP file uploads
- **LLM provider:** Google Gemini API
- **Rule format:** YARA
- **Language:** Python 3.x

## Repository Structure

```text
├── artifact_extractor.py    # Extracts entropy, metadata, and strings from files
├── rule_generator.py        # Calls the Gemini API to generate YARA syntax
├── rule_validator.py        # Compiles rules & tests against malicious/benign datasets
└── requirements.txt
```

## Setup & Usage

Assumes a working Python 3 environment and a Google Gemini API key exported as `GEMINI_API_KEY`.

```bash
# Install dependencies
pip install -r requirements.txt

# 1. Extract artefacts from a suspect file
python artifact_extractor.py --file /path/to/suspect.php --out artefacts.json

# 2. Generate a candidate YARA rule from the artefact bundle
python rule_generator.py --input artefacts.json --out rule.yar

# 3. Validate the rule against malicious + benign datasets
python rule_validator.py --rule rule.yar
```

## Datasets

- **Malicious (positive):** 480 PHP web shells — [Tennc Webshell Corpus](https://github.com/tennc/webshell), [SecLists](https://github.com/danielmiessler/SecLists)
- **Benign (negative):** Unmodified PHP source from WordPress, Joomla, and Drupal (false-positive control)

## Limitations & Future Work

- **Obfuscation is the ceiling.** Heavily obfuscated web shells evade static rules; pairing this with behavioural/dynamic analysis is the clear next step.
- **No response caching** on the Gemini integration — fine for research, but a real deployment needs rate-limit and cost controls.
- **Web-server-focused.** Extending coverage to endpoint and identity telemetry is a natural expansion.
- **Multi-format output.** Future iterations could emit Sigma rules alongside YARA, plus prompt-level guardrails to catch rules that are syntactically valid but semantically weak.

## What This Demonstrates

This work sits at the intersection of three live concerns in security operations: scaling detection engineering, reducing analyst alert fatigue, and integrating generative AI into defensive workflows in a controlled, *measured* way. It is intentionally lightweight and research-grade rather than production-hardened — the design priorities were investigative repeatability, deterministic feature extraction, and a clear line between AI-assisted output and human-validated production content.

## Author

**Aaquib Parvez** — MSc Cybersecurity, Northumbria University (2026)
SOC Analyst building AI tools to speed up threat detection.
[LinkedIn](https://linkedin.com/in/aaquibparvez) · [GitHub](https://github.com/aaquibbb)
