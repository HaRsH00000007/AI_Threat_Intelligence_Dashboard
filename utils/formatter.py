"""
Formatting utilities for output display
"""

from typing import Dict, Any, List
import json


def format_classification_result(result: Dict[str, Any]) -> str:
    """
    Format classification result for display
    
    Args:
        result: Classification result dictionary
    
    Returns:
        str: Formatted string
    """
    severity_icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }
    
    icon = severity_icons.get(result.get("severity", "MEDIUM"), "⚪")
    
    formatted = f"""
{'='*60}
THREAT CLASSIFICATION RESULT
{'='*60}

Threat Type: {result.get('threat_type', 'Unknown')}
Severity: {icon} {result.get('severity', 'Unknown')}
Confidence: {result.get('confidence', 0):.1%}

Summary:
{result.get('summary', 'No summary available')}

Key Indicators:
{chr(10).join('  • ' + ind for ind in result.get('indicators', []))}

Recommendations:
{chr(10).join(f'  {i+1}. {rec}' for i, rec in enumerate(result.get('recommendations', [])))}

{'='*60}
"""
    return formatted


def format_ioc_result(iocs: Dict[str, List[str]]) -> str:
    """
    Format IOC extraction result
    
    Args:
        iocs: IOC dictionary
    
    Returns:
        str: Formatted string
    """
    formatted = f"""
{'='*60}
INDICATORS OF COMPROMISE (IOCs)
{'='*60}

"""
    
    sections = {
        "ips": "IP Addresses",
        "urls": "URLs",
        "hashes": "File Hashes",
        "emails": "Email Addresses",
        "filenames": "Suspicious Files"
    }
    
    for key, title in sections.items():
        values = iocs.get(key, [])
        if values:
            formatted += f"\n{title} ({len(values)}):\n"
            for value in values:
                formatted += f"  • {value}\n"
    
    total = sum(len(v) for v in iocs.values())
    formatted += f"\nTotal IOCs Found: {total}\n"
    formatted += "="*60 + "\n"
    
    return formatted


def format_json_pretty(data: Dict[str, Any]) -> str:
    """
    Format dictionary as pretty JSON
    
    Args:
        data: Dictionary to format
    
    Returns:
        str: Pretty JSON string
    """
    return json.dumps(data, indent=2, ensure_ascii=False)


def format_table(headers: List[str], rows: List[List[Any]]) -> str:
    """
    Format data as ASCII table
    
    Args:
        headers: Column headers
        rows: Row data
    
    Returns:
        str: Formatted table
    """
    if not rows:
        return "No data to display"
    
    # Calculate column widths
    col_widths = [len(h) for h in headers]
    
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    
    # Build table
    separator = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    header_row = "|" + "|".join(f" {h:<{col_widths[i]}} " for i, h in enumerate(headers)) + "|"
    
    table = separator + "\n" + header_row + "\n" + separator + "\n"
    
    for row in rows:
        row_str = "|" + "|".join(f" {str(cell):<{col_widths[i]}} " for i, cell in enumerate(row)) + "|"
        table += row_str + "\n"
    
    table += separator
    
    return table


def format_timestamp(iso_timestamp: str) -> str:
    """
    Format ISO timestamp to readable format
    
    Args:
        iso_timestamp: ISO format timestamp
    
    Returns:
        str: Formatted timestamp
    """
    from datetime import datetime
    
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return iso_timestamp


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format
    
    Args:
        size_bytes: Size in bytes
    
    Returns:
        str: Formatted size
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"