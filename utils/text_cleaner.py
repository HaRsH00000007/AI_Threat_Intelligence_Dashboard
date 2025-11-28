"""
Text cleaning and preprocessing utilities
"""

import re


def clean_text(text: str) -> str:
    """
    Clean and normalize text for processing
    
    Args:
        text: Raw input text
    
    Returns:
        str: Cleaned text
    """
    if not text:
        return ""
    
    # Remove extra whitespace
    cleaned = re.sub(r'\s+', ' ', text)
    
    # Remove control characters
    cleaned = ''.join(char for char in cleaned if ord(char) >= 32 or char == '\n')
    
    # Strip leading/trailing whitespace
    cleaned = cleaned.strip()
    
    return cleaned


def truncate_text(text: str, max_length: int = 500) -> str:
    """
    Truncate text to maximum length
    
    Args:
        text: Input text
        max_length: Maximum character length
    
    Returns:
        str: Truncated text
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length] + "..."


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing invalid characters
    
    Args:
        filename: Original filename
    
    Returns:
        str: Sanitized filename
    """
    # Remove invalid filename characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Limit length
    if len(sanitized) > 200:
        name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
        sanitized = name[:195] + ('.' + ext if ext else '')
    
    return sanitized


def extract_domain(url: str) -> str:
    """
    Extract domain from URL
    
    Args:
        url: Full URL
    
    Returns:
        str: Domain name
    """
    pattern = r'(?:https?://)?(?:www\.)?([^/]+)'
    match = re.search(pattern, url)
    return match.group(1) if match else url


def mask_sensitive_data(text: str) -> str:
    """
    Mask sensitive data like passwords, API keys
    
    Args:
        text: Input text
    
    Returns:
        str: Text with masked sensitive data
    """
    # Mask API keys
    text = re.sub(r'api[_-]?key["\s:=]+[\w-]{20,}', 'api_key=***MASKED***', text, flags=re.IGNORECASE)
    
    # Mask passwords
    text = re.sub(r'password["\s:=]+\S+', 'password=***MASKED***', text, flags=re.IGNORECASE)
    
    # Mask tokens
    text = re.sub(r'token["\s:=]+[\w.-]{20,}', 'token=***MASKED***', text, flags=re.IGNORECASE)
    
    return text