# 🛡️ AI-Driven Cyber Security Threat Intelligence Dashboard

An advanced **AI-powered Threat Intelligence Dashboard** built using **Streamlit**, **Groq LLMs**, and **hybrid IOC analysis**.  
This system enables real-time monitoring, threat classification, IOC extraction, SOC-grade report generation, and vector embeddings for cyber security intelligence workflows.

---

## ⚡ Overview

This project provides a **full end-to-end cyber threat intelligence system** with:

- 🔴 **Live Threat Feed**
- 🔍 **Threat Classification (Groq LLM-powered)**
- 🎯 **IOC Extraction (Regex + AI Hybrid)**
- 📄 **Automated SOC Threat Report Generation**
- 🧬 **Embedding Generation for Threat Similarity**
- 🧠 **Groq LLM Integration (Mixtral + Llama Models)**

Built for Blue Teams, SOC Analysts, Researchers, and Cyber-Defense Automation.

---

## 🧩 Key Features

### 🔥 1. AI Threat Classification
Classifies threat text into:
- Malware  
- Ransomware  
- Phishing  
- DDoS  
- APT  
- Data Breach  
- Insider Threat  
- Other  

Outputs include:
- Threat type  
- Severity (Low → Critical)  
- Confidence score  
- Summary  
- Key indicators  
- Recommendations  

---

### 🎯 2. IOC Extractor
Hybrid detection combining:
- **Regex extraction** (IPs, URLs, hashes, emails, filenames)
- **Groq Mixtral LLM refinement**
- **AI-only mode**

Supports:
- IPv4 addresses  
- URL indicators  
- Email indicators  
- MD5/SHA1/SHA256 hashes  
- Suspicious filenames  

---

### 📝 3. SOC-Grade Threat Report Generator
Automatically produces structured JSON reports containing:
- Executive summary  
- Threat analysis  
- Risk level (Critical → Low)  
- Impact assessment  
- Extracted IOCs  
- Recommended mitigations  
- MITRE-style behavior mapping (AI generated)  

Fully customizable:
- Include/Exclude IOCs  
- Include/Exclude recommendations  
- Select report type  
  - Executive Summary  
  - Technical Analysis  
  - Incident Response  
  - Full Report  

---

### 🧬 4. Embedding Generator (Groq Llama 3 Embeddings)
Creates embeddings for:
- Threat logs  
- Alerts  
- Intelligence notes  
- IOCs  
- Incident descriptions  

Useful for:
- Similarity matching  
- Clustering  
- Threat correlation  
- Semantic search  

---

### 🔴 5. Live Threat Feed (Mock)
Shows 100% UI-compatible threat items such as:
- Brute-force attempts  
- Phishing URLs  
- Malware hashes  
- C2 infrastructure  
- Suspicious connections  

You can later replace mock feeds with:
- OTX  
- AbuseIPDB  
- PhishTank  
- MISP  
- VirusTotal  

---

## 🏗️ System Architecture

