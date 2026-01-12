# Automating Threat Detection and YARA Rule Generation using LLMs (Wazuh Integration)
 

## 📌 Project Overview
This repository contains the source code and technical implementation for the Master's dissertation titled:  
*> "Automating Threat Detection and YARA Rule Generation Using Large Language Models (LLM) for Wazuh in Web Server Environments"*


## 📂 Repository Structure

```text
├── Automating-Threat-Detection/
│   ├── artifact_extractor.py    # Extracts entropy, metadata, and strings from files [cite: 521]
│   ├── rule_generator.py        # Interact with Gemini API to generate YARA syntax [cite: 531]
│   ├── rule_validator.py        # Compiles rules & checks against benign datasets [cite: 531]
