"""
Threat Classification Service
Classifies security threats using Groq LLMs
"""

from typing import Dict, Any, List
from services.groq_client import chat_completion_json
from utils.text_cleaner import clean_text
from utils.logger import log_activity


def classify_threat(threat_text: str) -> Dict[str, Any]:
    """
    Classify security threat using AI analysis
    
    Args:
        threat_text: Raw threat description or security alert
    
    Returns:
        dict: Classification results containing:
            - threat_type: Type of threat (Malware, Phishing, etc.)
            - severity: CRITICAL, HIGH, MEDIUM, LOW
            - confidence: Float between 0-1
            - summary: Brief analysis summary
            - indicators: List of key indicators
            - recommendations: List of recommended actions
    
    Raises:
        Exception: If classification fails
    """
    try:
        # Clean input text
        cleaned_text = clean_text(threat_text)
        
        # Construct classification prompt
        system_prompt = """You are an expert cybersecurity threat analyst. Analyze the provided security threat description and provide a comprehensive classification.

Your response must be a valid JSON object with the following structure:
{
    "threat_type": "one of: Malware, Phishing, Ransomware, DDoS, Data Breach, Insider Threat, APT, Social Engineering, Zero-Day, Supply Chain Attack, Other",
    "severity": "one of: CRITICAL, HIGH, MEDIUM, LOW",
    "confidence": 0.85,
    "summary": "2-3 sentence summary of the threat",
    "indicators": ["list", "of", "key", "threat", "indicators"],
    "recommendations": ["list", "of", "recommended", "actions"]
}

Consider:
- Attack vectors and techniques
- Potential impact on systems and data
- Urgency of response required
- Known threat patterns and TTPs"""

        user_prompt = f"""Analyze this security threat:

{cleaned_text}

Provide a comprehensive threat classification in JSON format."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        # Get classification from Groq
        result = chat_completion_json(messages)
        
        # Validate and normalize result
        classification = _validate_classification(result)
        
        log_activity(
            "classification",
            f"Threat classified as {classification['threat_type']} with {classification['severity']} severity"
        )
        
        return classification
    
    except Exception as e:
        log_activity("error", f"Classification failed: {str(e)}")
        raise Exception(f"Threat classification error: {str(e)}")


def _validate_classification(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and normalize classification results
    
    Args:
        result: Raw classification result from LLM
    
    Returns:
        dict: Validated and normalized classification
    """
    # Valid values
    valid_threat_types = {
        "Malware", "Phishing", "Ransomware", "DDoS", "Data Breach",
        "Insider Threat", "APT", "Social Engineering", "Zero-Day",
        "Supply Chain Attack", "Other"
    }
    
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    
    # Normalize threat type
    threat_type = result.get("threat_type", "Other")
    if threat_type not in valid_threat_types:
        threat_type = "Other"
    
    # Normalize severity
    severity = result.get("severity", "MEDIUM").upper()
    if severity not in valid_severities:
        severity = "MEDIUM"
    
    # Validate confidence
    confidence = float(result.get("confidence", 0.7))
    confidence = max(0.0, min(1.0, confidence))
    
    # Ensure lists
    indicators = result.get("indicators", [])
    if not isinstance(indicators, list):
        indicators = []
    
    recommendations = result.get("recommendations", [])
    if not isinstance(recommendations, list):
        recommendations = []
    
    # Build validated result
    validated = {
        "threat_type": threat_type,
        "severity": severity,
        "confidence": confidence,
        "summary": result.get("summary", "Threat analysis completed."),
        "indicators": indicators[:10],  # Limit to 10 indicators
        "recommendations": recommendations[:10]  # Limit to 10 recommendations
    }
    
    return validated


def batch_classify_threats(threats: List[str]) -> List[Dict[str, Any]]:
    """
    Classify multiple threats in batch
    
    Args:
        threats: List of threat descriptions
    
    Returns:
        list: List of classification results
    """
    results = []
    
    for idx, threat in enumerate(threats):
        try:
            result = classify_threat(threat)
            results.append(result)
            log_activity("info", f"Batch classification {idx + 1}/{len(threats)} completed")
        except Exception as e:
            log_activity("error", f"Batch classification {idx + 1} failed: {str(e)}")
            results.append({
                "threat_type": "Unknown",
                "severity": "MEDIUM",
                "confidence": 0.0,
                "summary": f"Classification failed: {str(e)}",
                "indicators": [],
                "recommendations": []
            })
    
    return results


def get_threat_statistics(classifications: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate statistics from multiple classifications
    
    Args:
        classifications: List of classification results
    
    Returns:
        dict: Statistical summary
    """
    if not classifications:
        return {}
    
    from collections import Counter
    
    threat_types = Counter(c["threat_type"] for c in classifications)
    severities = Counter(c["severity"] for c in classifications)
    avg_confidence = sum(c["confidence"] for c in classifications) / len(classifications)
    
    return {
        "total_threats": len(classifications),
        "threat_type_distribution": dict(threat_types),
        "severity_distribution": dict(severities),
        "average_confidence": round(avg_confidence, 2),
        "highest_severity_count": severities.get("CRITICAL", 0) + severities.get("HIGH", 0)
    }