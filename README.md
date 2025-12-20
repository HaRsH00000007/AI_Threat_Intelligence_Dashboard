# 🛡️ AI Threat Intelligence Dashboard

An **AI-driven Cyber Security Threat Intelligence Dashboard** that leverages **Large Language Models (LLMs)** to assist Blue Teams and SOC analysts in **threat classification, IOC extraction, automated report generation, and threat intelligence analysis**.

This project explores how **AI + Cyber Security** can work together to reduce manual effort in log analysis, threat triage, and incident reporting.

---

## 🚀 Project Motivation

Cyber security teams deal with massive amounts of logs, alerts, and threat intelligence data every day.  
Manual analysis is time-consuming and error-prone.

This project was built to experiment with:
- How **LLMs can assist SOC workflows**
- How AI can **classify threats from raw logs**
- How Indicators of Compromise (IOCs) can be **automatically extracted**
- How **SOC-grade reports** can be generated using AI

The goal is not to replace analysts, but to **augment Blue Team operations** using AI.

---

## 🧠 What This Project Does

The dashboard provides **five core capabilities**:

### 🔴 Live Threat Feed
- Displays real-time (mock) threat intelligence events
- Includes brute-force attempts, phishing URLs, malware hashes, and C2 indicators
- Designed to be easily extendable to real feeds (OTX, VirusTotal, MISP, AbuseIPDB)

---

### 🔍 AI-Powered Threat Classification
- Classifies raw threat text or logs using **Groq Mixtral LLM**
- Outputs:
  - Threat type (Malware, Phishing, Ransomware, DDoS, APT, etc.)
  - Severity level
  - Confidence score
  - Summary
  - Key indicators
  - Recommended actions

This simulates **SOC alert triage automation**.

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

Hybrid mode provides higher accuracy by combining deterministic rules with AI reasoning.

---

### 📄 SOC-Grade Threat Report Generator
- Automatically generates structured cyber security reports using LLMs
- Report includes:
  - Executive summary
  - Threat analysis
  - Impact assessment
  - Risk level
  - IOCs
  - Recommended mitigations
- Output is **clean JSON**, ready for:
  - Incident response documentation
  - Ticketing systems
  - SOC reporting

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
    │     └── Application & error logging
    │
    ├── formatter.py
    │     └── Output & UI formatting
    │
    └── text_cleaner.py
          └── Text preprocessing & normalization




