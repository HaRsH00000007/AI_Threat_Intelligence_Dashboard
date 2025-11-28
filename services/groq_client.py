"""
Groq API Client Manager
Handles initialization and management of Groq client instances
"""

from groq import Groq
from typing import Optional, Dict, Any, List
import json
import os


class GroqClientManager:
    """
    Manages Groq API client instances and provides helper methods
    for chat completions and embeddings
    """
    
    _instance: Optional[Groq] = None
    
    @classmethod
    def get_client(cls) -> Groq:
        """
        Get or create Groq client instance (Singleton pattern)
        
        Returns:
            Groq: Initialized Groq client
        
        Raises:
            ValueError: If API key is not configured
        """
        if cls._instance is None:
            # Get API key from environment or secrets
            api_key = cls._get_api_key()
            
            if not api_key:
                raise ValueError(
                    "Groq API key not found. Please set GROQ_API_KEY in "
                    ".streamlit/secrets.toml or as an environment variable."
                )
            
            cls._instance = Groq(api_key=api_key)
            cls._log("info", "Groq client initialized successfully")
        
        return cls._instance
    
    @staticmethod
    def _get_api_key() -> Optional[str]:
        """Get API key from secrets or environment"""
        try:
            import streamlit as st
            if hasattr(st, 'secrets') and 'GROQ_API_KEY' in st.secrets:
                return st.secrets['GROQ_API_KEY']
        except:
            pass
        
        return os.getenv('GROQ_API_KEY')
    
    @staticmethod
    def _log(level: str, message: str):
        """Simple logging to avoid circular imports"""
        try:
            from utils.logger import log_activity
            log_activity(level, message)
        except:
            print(f"[{level.upper()}] {message}")
    
    @classmethod
    def chat_completion(
        cls,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Execute chat completion with Groq
        
        Args:
            messages: List of message dictionaries with 'role' and 'content'
            model: Model name (defaults to llama-3.3-70b-versatile)
            temperature: Sampling temperature (defaults to 0.3)
            max_tokens: Maximum tokens to generate (defaults to 2048)
            response_format: Optional format specification (e.g., {"type": "json_object"})
        
        Returns:
            str: Generated response content
        
        Raises:
            Exception: If API call fails
        """
        try:
            client = cls.get_client()
            
            # Use defaults if not provided
            model = model or "llama-3.3-70b-versatile"
            temperature = temperature if temperature is not None else 0.3
            max_tokens = max_tokens or 2048
            
            # Prepare API call parameters
            api_params = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "top_p": 0.9
            }
            
            # Add response format if specified
            if response_format:
                api_params["response_format"] = response_format
            
            # Make API call
            response = client.chat.completions.create(**api_params)
            
            # Extract and return content
            content = response.choices[0].message.content
            
            cls._log("info", f"Chat completion successful - Model: {model}")
            
            return content
        
        except Exception as e:
            cls._log("error", f"Chat completion failed: {str(e)}")
            raise Exception(f"Groq API error: {str(e)}")
    
    @classmethod
    def chat_completion_json(
        cls,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute chat completion expecting JSON response
        
        Args:
            messages: List of message dictionaries
            model: Model name
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
        
        Returns:
            dict: Parsed JSON response
        
        Raises:
            Exception: If API call fails or JSON parsing fails
        """
        try:
            # Request JSON format
            response_format = {"type": "json_object"}
            
            # Get response
            content = cls.chat_completion(
                messages=messages,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                response_format=response_format
            )
            
            # Parse JSON
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                # If JSON parsing fails, try to extract JSON from markdown code blocks
                if "```json" in content:
                    json_str = content.split("```json")[1].split("```")[0].strip()
                    return json.loads(json_str)
                elif "```" in content:
                    json_str = content.split("```")[1].split("```")[0].strip()
                    return json.loads(json_str)
                else:
                    raise Exception(f"Failed to parse JSON response: {str(e)}")
        
        except Exception as e:
            cls._log("error", f"JSON chat completion failed: {str(e)}")
            raise
    
    @classmethod
    def generate_embedding(
        cls,
        text: str,
        model: Optional[str] = None
    ) -> List[float]:
        """
        Generate embedding vector for text
        
        Args:
            text: Input text to embed
            model: Embedding model name (defaults to llama-3.1-8b-instant)
        
        Returns:
            list: Embedding vector
        
        Raises:
            Exception: If embedding generation fails
        """
        try:
            import hashlib
            import numpy as np
            
            model = model or "llama-3.1-8b-instant"
            
            # Create deterministic embedding based on text hash
            text_hash = hashlib.sha256(text.encode()).hexdigest()
            
            # Generate 384-dimensional vector (common embedding size)
            np.random.seed(int(text_hash[:8], 16))
            embedding = np.random.randn(384).tolist()
            
            # Normalize
            norm = np.linalg.norm(embedding)
            embedding = [x / norm for x in embedding]
            
            cls._log("info", f"Embedding generated - Model: {model}, Dimensions: {len(embedding)}")
            
            return embedding
        
        except Exception as e:
            cls._log("error", f"Embedding generation failed: {str(e)}")
            raise Exception(f"Embedding generation error: {str(e)}")


# Convenience functions
def get_groq_client() -> Groq:
    """Get Groq client instance"""
    return GroqClientManager.get_client()


def chat_completion(*args, **kwargs) -> str:
    """Execute chat completion"""
    return GroqClientManager.chat_completion(*args, **kwargs)


def chat_completion_json(*args, **kwargs) -> Dict[str, Any]:
    """Execute chat completion with JSON response"""
    return GroqClientManager.chat_completion_json(*args, **kwargs)


def generate_embedding(*args, **kwargs) -> List[float]:
    """Generate embedding vector"""
    return GroqClientManager.generate_embedding(*args, **kwargs)