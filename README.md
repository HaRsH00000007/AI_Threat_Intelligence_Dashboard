# 🛡️ AI Threat Intelligence Dashboard

An **AI-driven Cyber Security Threat Intelligence Dashboard** that leverages **Large Language Models (LLMs)** to assist Blue Teams and SOC analysts in **threat classification, IOC extraction, automated report generation, and threat intelligence analysis**.

This project demonstrates how **AI meets Cyber Security** to reduce manual effort in log analysis, threat triage, and incident reporting.

---

## 🚀 Project Motivation

Cyber security teams process huge volumes of logs, alerts, and threat intelligence every day.  
Manual analysis is time-consuming and error-prone.

This project was built to explore:
- How **LLMs can assist SOC workflows**
- How AI can **classify threats from raw logs**
- How IOCs can be **automatically extracted**
- How **SOC-grade threat reports** can be generated using AI

The goal is not to replace analysts, but to **augment Blue Team operations**.

---

## 🧠 What This Project Does

The dashboard provides **five core capabilities**:

### 🔴 Live Threat Feed
- Displays real-time (mock) cyber threat events
- Includes brute-force attempts, phishing URLs, malware hashes, and C2 indicators
- Easily extendable to real feeds (OTX, MISP, VirusTotal, AbuseIPDB)

---

### 🔍 AI-Powered Threat Classification
- Classifies raw threat text or logs using **Groq Mixtral LLM**
- Outputs:
  - Threat type
  - Severity level
  - Confidence score
  - Summary
  - Key indicators
  - Recommended actions

Simulates SOC alert triage automation.

---

### 🎯 IOC Extraction (Hybrid Regex + AI)
- Extracts **Indicators of Compromise (IOCs)** such as:
  - IP addresses
  - URLs / domains
  - File hashes (MD5 / SHA1 / SHA256)
  - Email addresses
  - Suspicious filenames
- Supports three modes:
  - Regex Only
  - AI Only
  - Hybrid (Regex + LLM enhancement)

---

### 📄 SOC-Grade Threat Report Generator
- Automatically generates structured cyber security reports using LLMs
- Includes:
  - Executive summary
  - Threat analysis
  - Impact assessment
  - Risk level
  - IOCs
  - Recommended mitigations
- Output is **clean JSON**, ready for incident response workflows

---

### 🧬 Threat Intelligence Embedding Generator
- Generates vector embeddings for threat data
- Useful for:
  - Threat similarity analysis
  - Clustering related incidents
  - Semantic search
  - Building threat intelligence knowledge bases

---

## 🏗️ System Architecture

```text
Streamlit UI (app.py)
│
├── Services Layer
│   ├── groq_client.py
│   │     └── Groq API wrapper (LLM calls & embeddings)
│   │
│   ├── classifier_service.py
│   │     └── AI-powered threat classification
│   │
│   ├── ioc_extractor.py
│   │     └── Hybrid IOC extraction (Regex + LLM)
│   │
│   ├── report_service.py
│   │     └── SOC-grade threat report generation
│   │
│   ├── feed_service.py
│   │     └── Live threat feed (mock / API-ready)
│   │
│   └── vector_service.py
│         └── Threat embedding generation
│
└── Utils Layer
    ├── logger.py
    │     └── Logging utilities
    │
    ├── formatter.py
    │     └── Output formatting
    │
    └── text_cleaner.py
          └── Text preprocessing
```
---
## 📁 Project Structure
```text
AI_Threat_Intelligence_Dashboard/
│
├── app.py
├── requirements.txt
│
├── services/
│   ├── groq_client.py
│   ├── classifier_service.py
│   ├── ioc_extractor.py
│   ├── report_service.py
│   ├── feed_service.py
│   └── vector_service.py
│
├── utils/
│   ├── logger.py
│   ├── formatter.py
│   └── text_cleaner.py
│
├── data/
│   ├── logs/
│   ├── vectors/
│   └── stored_reports/
│
└── .streamlit/
    ├── secrets.toml
    └── config.toml
```
---
## 🔑 Groq API Key Setup
Create the file:
```text
.streamlit/secrets.toml
```
Add your API key:
```text
GROQ_API_KEY = "your_groq_api_key_here"
```
⚠️ Do NOT store API keys in config.toml
---
## ⚙️ Installation & Setup
```text
git clone https://github.com/HaRsH00000007/AI_Threat_Intelligence_Dashboard
cd AI_Threat_Intelligence_Dashboard

python -m venv venv
venv\Scripts\activate   # Windows

pip install -r requirements.txt

```
---




