# ============================================
# utils/__init__.py
# ============================================
"""
Utilities package for AI Threat Intelligence Dashboard
Contains helper functions only.
Do NOT import any 'services' modules here 
to avoid circular dependency.
"""

from utils.text_cleaner import (
    clean_text,
    truncate_text,
    sanitize_filename
)

from utils.logger import (
    log_activity,
    log_api_call,
    get_logger
)

from utils.formatter import (
    format_classification_result,
    format_ioc_result,
    format_json_pretty,
    format_table
)

__all__ = [
    # Text cleaning utilities
    'clean_text',
    'truncate_text',
    'sanitize_filename',

    # Logging utilities
    'log_activity',
    'log_api_call',
    'get_logger',

    # Formatting utilities
    'format_classification_result',
    'format_ioc_result',
    'format_json_pretty',
    'format_table'
]
