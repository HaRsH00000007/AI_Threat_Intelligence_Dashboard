"""
services/report_service.py
Generates detailed SOC-grade threat reports using Groq LLM.
"""

from typing import Dict, Any
from services.groq_client import chat_completion_json
from services.ioc_extractor import extract_iocs


def _build_prompt(text: str, report_type: str, include_iocs: bool, include_recommendations: bool, regex_iocs: Dict) -> str:
    """
    Construct prompt for LLM to generate a structured threat report.
    """
    ioc_section = f"Regex/AI extracted IOCs:\n{regex_iocs}\n" if include_iocs else "Do not include an IOC section.\n"
    rec_section = "Include detailed recommended mitigation steps.\n" if include_recommendations else "Do not include recommendations.\n"

    prompt = f"""
You are a senior SOC (Security Operations Center) analyst. 
Generate a **{report_type}** style threat intelligence report.

Input Threat Data:
\"\"\"{text}\"\"\"

{ioc_section}
{rec_section}

Your output MUST BE VALID JSON ONLY (no markdown).
Use EXACTLY these JSON keys:

{{
  "executive_summary": "",
  "threat_analysis": "",
  "impact_assessment": "",
  "risk_level": "",        // CRITICAL, HIGH, MEDIUM, LOW
  "iocs": {{
      "ips": [],
      "urls": [],
      "hashes": [],
      "emails": [],
      "filenames": []
  }},
  "recommendations": []     // optional if disabled
}}

Rules:
- Keep the JSON clean and strictly valid.
- Tailor the detail level based on report_type.
- Always include iocs ONLY if include_iocs=True.
- Always include recommendations ONLY if include_recommendations=True.
"""

    return prompt


def generate_threat_report(
    text: str,
    report_type: str = "Full Report",
    include_iocs: bool = True,
    include_recommendations: bool = True,
    model: str = "mixtral-8x7b-32768"
) -> Dict[str, Any]:
    """
    Generate detailed SOC-style threat reports with full customization.

    Args:
        text: Threat description or incident details.
        report_type: Executive Summary | Technical Analysis | Incident Response | Full Report
        include_iocs: Whether to include IOC details
        include_recommendations: Whether to include recommended actions
        model: Groq model name

    Returns:
        dict: A structured report compatible with app.py UI
    """
    
    # Step 1: Extract IOCs if enabled
    if include_iocs:
        regex_iocs = extract_iocs(text)
    else:
        regex_iocs = {"ips": [], "urls": [], "hashes": [], "emails": [], "filenames": []}

    # Step 2: Build LLM prompt
    prompt = _build_prompt(text, report_type, include_iocs, include_recommendations, regex_iocs)

    # Step 3: Call Groq LLM
    try:
        response = chat_completion_json(
            messages=[{"role": "user", "content": prompt}],
            model=model,
            temperature=0.05,
            max_tokens=2000
        )

        # Ensure missing fields exist
        response.setdefault("iocs", regex_iocs)
        response.setdefault("recommendations", [])
        response.setdefault("impact_assessment", "No impact assessment provided.")
        response.setdefault("threat_analysis", "No threat analysis available.")
        response.setdefault("executive_summary", "No summary generated.")
        response.setdefault("risk_level", "MEDIUM")

        return response

    except Exception as e:
        # Fallback minimal report
        return {
            "executive_summary": f"LLM failed: {str(e)}",
            "threat_analysis": "Not available.",
            "impact_assessment": "Not available.",
            "risk_level": "LOW",
            "iocs": regex_iocs,
            "recommendations": [
                "Verify system logs.",
                "Monitor for repeated anomalies.",
                "Apply appropriate patches."
            ] if include_recommendations else []
        }
