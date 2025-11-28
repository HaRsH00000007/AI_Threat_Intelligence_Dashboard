"""
IOC Extractor Service
Performs regex-based IOC extraction and optional LLM enhancement using Groq.
"""

import re
from typing import Dict, List
from services.groq_client import chat_completion_json


# ==========================
# REGEX PATTERNS
# ==========================

IPV4_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
URL_REGEX = r"http[s]?://[^\s\]\[<>\"']+"
HASH_REGEX = r"\b[a-fA-F0-9]{32,64}\b"   # MD5, SHA1, SHA256
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
FILENAME_REGEX = r"\b[\w\-.]+\.(exe|dll|ps1|bat|sh|js)\b"


# ==========================
# STEP 1: REGEX Extraction
# ==========================

def extract_iocs_regex(text: str) -> Dict[str, List[str]]:
    """
    Extract IOCs using regex.
    """

    ips = re.findall(IPV4_REGEX, text)
    urls = re.findall(URL_REGEX, text)
    hashes = re.findall(HASH_REGEX, text)
    emails = re.findall(EMAIL_REGEX, text)
    filenames = re.findall(FILENAME_REGEX, text)

    return {
        "ips": list(set(ips)),
        "urls": list(set(urls)),
        "hashes": list(set(hashes)),
        "emails": list(set(emails)),
        "filenames": list(set([f[0] if isinstance(f, tuple) else f for f in filenames])),
    }


# ==========================
# STEP 2: LLM Enhancement
# ==========================

def enhance_iocs_with_llm(text: str, regex_iocs: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """
    Use Groq LLM to improve IOC detection:
    - discover missed IOCs
    - remove false positives
    - standardize output
    """

    prompt = f"""
You are a cybersecurity analyst. Extract all Indicators of Compromise from the text.

Text:
{text}

Regex-based IOCs already found:
{regex_iocs}

Your job:
1. Add any missing IOCs.
2. Remove invalid or false positives.
3. Ensure ALL IOCs are extracted.
4. Output ONLY valid JSON in this format:

{{
    "ips": [],
    "urls": [],
    "hashes": [],
    "emails": [],
    "filenames": []
}}
"""

    try:
        response = chat_completion_json(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            model="llama-3.3-70b-versatile"
        )
        return response

    except Exception:
        # Fallback — return regex results if LLM fails
        return regex_iocs


# ==========================
# PUBLIC FUNCTION (USED BY APP)
# ==========================

def extract_iocs(text: str, method: str = "hybrid") -> Dict[str, List[str]]:
    """
    Extract IOCs using one of three methods:
    - hybrid: regex + LLM enhancement
    - regex_only: regex only
    - ai_only: Groq AI only
    """
    
    method = method.lower()

    # STEP 1 - Always run regex
    regex_iocs = extract_iocs_regex(text)

    # regex only mode
    if method == "regex_only":
        return regex_iocs

    # ai only mode → ignore regex, run LLM on full text
    if method == "ai_only":
        prompt = f"""
        Extract all IOCs from the following text.
        Return ONLY valid JSON in this format:
        {{
            "ips": [],
            "urls": [],
            "hashes": [],
            "emails": [],
            "filenames": []
        }}

        Text:
        {text}
        """

        try:
            response = chat_completion_json(
                messages=[{"role": "user", "content": prompt}],
                model="mixtral-8x7b-32768",
                temperature=0.1
            )
            return response
        except:
            # fallback: if LLM fails, return empty IOC set
            return {
                "ips": [],
                "urls": [],
                "hashes": [],
                "emails": [],
                "filenames": []
            }

    # default hybrid mode: regex + LLM enhancement
    return enhance_iocs_with_llm(text, regex_iocs)



# ==========================
# OPTIONAL: IOC Severity
# ==========================

def categorize_ioc_severity(iocs: Dict[str, List[str]]) -> Dict[str, Dict[str, str]]:
    """
    Assign a simple severity level to each IOC type.
    
    Example logic:
    - IPs linked to attacks → High
    - URLs → Medium
    - Hashes → High (malware)
    - Emails → Low (depends)
    """

    severity_map = {}

    for ip in iocs.get("ips", []):
        severity_map[ip] = "high"

    for url in iocs.get("urls", []):
        severity_map[url] = "medium"

    for h in iocs.get("hashes", []):
        severity_map[h] = "high"

    for email in iocs.get("emails", []):
        severity_map[email] = "low"

    for fname in iocs.get("filenames", []):
        severity_map[fname] = "medium"

    return severity_map
