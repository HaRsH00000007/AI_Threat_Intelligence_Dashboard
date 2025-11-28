"""
services/feed_service.py

Provides mock threat intelligence feed data
compatible with app.py UI.
"""

from typing import List, Dict
from datetime import datetime


def get_live_threats() -> List[Dict]:
    """
    Returns a mock list of active threat intelligence items
    formatted to match app.py expectations.
    """

    return [
        {
            "title": "SSH Brute Force Attempt",
            "description": "Multiple failed SSH login attempts detected from a known malicious IP.",
            "source": "AbuseIPDB",
            "type": "Brute-force SSH",
            "ioc": "185.122.44.18",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": 7,
        },
        {
            "title": "Phishing URL Detected",
            "description": "A PayPal credential-harvesting site has been identified.",
            "source": "PhishTank",
            "type": "Phishing URL",
            "ioc": "http://secure-paypal-alert.com/login",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": 6,
        },
        {
            "title": "Malware SHA256 Hash",
            "description": "A suspicious executable hash flagged by VirusTotal.",
            "source": "VirusTotal",
            "type": "Malware Sample",
            "ioc": "a9f5d3c82e998a937de23b75f0f1b5aa...",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": 8,
        },
        {
            "title": "C2 Server Communication",
            "description": "Outbound connection attempt to a known command-and-control IP.",
            "source": "AlienVault OTX",
            "type": "C2 Infrastructure",
            "ioc": "103.42.55.211",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": 9,
        }
    ]


def get_threat_statistics() -> Dict:
    """
    Returns simple statistics for dashboards.
    """

    threats = get_live_threats()

    total = len(threats)
    high_severity = len([t for t in threats if t["severity"] >= 7])
    sources = list(set(t["source"] for t in threats))

    return {
        "total_threats": total,
        "high_severity": high_severity,
        "unique_sources": len(sources),
        "sources": sources,
    }
