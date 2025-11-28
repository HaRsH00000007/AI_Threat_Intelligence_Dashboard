"""
Configuration settings for AI Threat Intelligence Dashboard
Handles API keys, model configurations, and system settings
"""

import os


class Settings:
    """Centralized configuration management"""
    
    # Model Configurations
    CHAT_MODEL = "llama-3.3-70b-versatile"  # Primary chat model
    CHAT_MODEL_ALTERNATIVE = "llama3-8b-8192"  # Alternative model
    EMBEDDING_MODEL = "llama-3.1-8b-instant"  # Embedding model
    
    # API Settings
    MAX_TOKENS = 2048
    TEMPERATURE = 0.3  # Lower for more deterministic outputs
    TOP_P = 0.9
    
    # System Settings
    LOG_LEVEL = "INFO"
    LOG_FILE = "data/logs/app.log"
    
    # Data Storage
    REPORTS_DIR = "data/stored_reports"
    VECTORS_DIR = "data/vectors"
    LOGS_DIR = "data/logs"
    
    # IOC Extraction Settings
    IOC_CONFIDENCE_THRESHOLD = 0.7
    MAX_IOC_EXTRACTION_ATTEMPTS = 3
    
    # Threat Feed Settings
    FEED_REFRESH_INTERVAL = 300  # seconds
    MAX_FEED_ITEMS = 10
    
    # UI Settings
    PAGE_TITLE = "AI Threat Intelligence Dashboard"
    PAGE_ICON = "🛡️"
    LAYOUT = "wide"
    
    @staticmethod
    def get_groq_api_key():
        """
        Retrieve Groq API key from secrets or environment
        Priority: Streamlit secrets > Environment variable
        """
        try:
            import streamlit as st
            if hasattr(st, 'secrets') and 'GROQ_API_KEY' in st.secrets:
                return st.secrets['GROQ_API_KEY']
        except:
            pass
        
        return os.getenv('GROQ_API_KEY')
    
    @classmethod
    def validate_config(cls):
        """
        Validate that all required configurations are present
        
        Returns:
            bool: True if configuration is valid
        """
        # Create necessary directories
        os.makedirs(cls.REPORTS_DIR, exist_ok=True)
        os.makedirs(cls.VECTORS_DIR, exist_ok=True)
        os.makedirs(cls.LOGS_DIR, exist_ok=True)
        
        return True
    
    @classmethod
    def get_model_config(cls):
        """
        Get complete model configuration
        
        Returns:
            dict: Model configuration parameters
        """
        return {
            "chat_model": cls.CHAT_MODEL,
            "embedding_model": cls.EMBEDDING_MODEL,
            "max_tokens": cls.MAX_TOKENS,
            "temperature": cls.TEMPERATURE,
            "top_p": cls.TOP_P
        }


# Create settings instance
settings = Settings()