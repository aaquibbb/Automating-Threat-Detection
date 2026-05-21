# Automating Threat Detection and YARA Rule Generation using LLMs (Wazuh Integration)
 

## 📌 Project Overview
This repository contains the source code and technical implementation for the Master's dissertation titled:  
*> "Automating Threat Detection and YARA Rule Generation Using Large Language Models (LLM) for Wazuh in Web Server Environments"*


## 📂 Repository Structure

```text
├── Automating-Threat-Detection/
│   ├── artifact_extractor.py    # Extracts entropy, metadata, and strings from files
│   ├── rule_generator.py        # Interact with Gemini API to generate YARA syntax 
│   ├── rule_validator.py        # Compiles rules & checks against benign datasets 
```
## Technology Stack

- **Detection Platform:** Wazuh XDR (file integrity monitoring, alert pipeline)
- **LLM Provider:** Google Gemini API
- **Rule Format:** YARA
- **Telemetry Source:** Nginx access and error logs
- **Language:** Python 3.x

## Setup and Usage

The pipeline assumes a working Python 3 environment and a Google Gemini API key exported as the `GEMINI_API_KEY` environment variable.

```bash
# Install dependencies
pip install -r requirements.txt

# Extract artefacts from a suspect file
python artefact_extractor.py --file /path/to/suspect.bin --out artefacts.json

# Generate a candidate YARA rule from the artefact bundle
python rule_generator.py --input artefacts.json --out rule.yar

# Summarise Nginx logs for analyst triage
python nginx_log_summarizer.py --logs /var/log/nginx/access.log
```

## What This Project Demonstrates

This work sits at the intersection of three current concerns in security operations: scaling detection engineering, reducing analyst alert fatigue, and integrating generative AI into defensive workflows in a controlled and validated way. It is intentionally lightweight rather than production-grade. The design priorities were investigative repeatability, deterministic feature extraction before any model interaction, and clear separation between AI-assisted output and human-validated production content.

## Limitations and Future Work

- The current rule validation step relies on manual review against benign datasets; an automated regression harness would improve repeatability.
- The Gemini integration assumes API availability and does not cache responses, which is acceptable for research but would need rate limit and cost controls in any operational context.
- Coverage is currently focused on web server compromise patterns; extending to endpoint and identity telemetry is a natural next step.
- Future iterations could integrate Sigma rule output alongside YARA and add prompt-level guardrails to detect cases where the model produces structurally valid but semantically weak detection logic.

## Author

Aaquib Parvez — MSc Cybersecurity, Northumbria University, 2026.
LinkedIn: [linkedin.com/in/aaquibparvez](https://linkedin.com/in/aaquibparvez)
