"""
ProjectLibra - LLM Factory
Factory for creating LLM clients based on configuration
"""

import logging
from typing import Dict, Any, Optional

from .base_client import BaseLLMClient, LLMConfig, LLMProvider
from .openai_client import OpenAIClient
from .ollama_client import OllamaClient
from .groq_client import GroqClient
from .gemini_client import GeminiClient

logger = logging.getLogger(__name__)


class LLMFactory:
    """
    Factory for creating LLM clients.
    Supports multiple providers with automatic fallback.
    """
    
    PROVIDERS = {
        'openai': OpenAIClient,
        'ollama': OllamaClient,
        'groq': GroqClient,
        'gemini': GeminiClient
    }
    
    DEFAULT_MODELS = {
        'gemini': 'gemini-flash-latest',
        'openai': 'gpt-5.2',
        'ollama': 'llama2',
        'groq': 'llama-3.1-70b-versatile'
    }
    
    @classmethod
    def create(cls, 
               provider: str,
               api_key: Optional[str] = None,
               model: Optional[str] = None,
               base_url: Optional[str] = None,
               **kwargs) -> BaseLLMClient:
        """
        Create an LLM client for the specified provider.
        
        Args:
            provider: LLM provider name (openai, ollama, groq, gemini)
            api_key: API key for the provider
            model: Model name (uses default if not specified)
            base_url: Custom base URL (for Ollama)
            **kwargs: Additional configuration parameters
            
        Returns:
            Configured LLM client
            
        Raises:
            ValueError: If provider is unknown
        """
        provider = provider.lower()
        
        if provider not in cls.PROVIDERS:
            raise ValueError(f"Unknown LLM provider: {provider}. "
                           f"Supported: {list(cls.PROVIDERS.keys())}")
        
        config = LLMConfig(
            provider=provider,
            model=model or cls.DEFAULT_MODELS.get(provider),
            api_key=api_key,
            base_url=base_url,
            max_tokens=kwargs.get('max_tokens', 4096),
            temperature=kwargs.get('temperature', 0.7),
            timeout=kwargs.get('timeout', 60),
            retry_attempts=kwargs.get('retry_attempts', 3),
            extra_params=kwargs.get('extra_params', {})
        )
        
        client_class = cls.PROVIDERS[provider]
        
        try:
            client = client_class(config)
            logger.info(f"Created {provider} client with model: {config.model}")
            return client
        except Exception as e:
            logger.error(f"Failed to create {provider} client: {e}")
            raise
    
    @classmethod
    def create_from_config(cls, config: Dict[str, Any]) -> BaseLLMClient:
        """
        Create an LLM client from a configuration dictionary.
        
        Args:
            config: Configuration dictionary with provider settings
            
        Returns:
            Configured LLM client
        """
        provider = config.get('provider', 'gemini')
        
        return cls.create(
            provider=provider,
            api_key=config.get('api_key'),
            model=config.get('model'),
            base_url=config.get('base_url'),
            max_tokens=config.get('max_tokens', 4096),
            temperature=config.get('temperature', 0.7),
            timeout=config.get('timeout', 60)
        )
    
    @classmethod
    def create_with_fallback(cls, 
                              providers: list,
                              configs: Dict[str, Dict]) -> BaseLLMClient:
        """
        Create an LLM client with fallback providers.
        Tries each provider in order until one succeeds.
        
        Args:
            providers: List of provider names in preference order
            configs: Configuration for each provider
            
        Returns:
            First successfully created client
            
        Raises:
            RuntimeError: If all providers fail
        """
        errors = []
        
        for provider in providers:
            if provider not in configs:
                continue
                
            try:
                config = configs[provider]
                client = cls.create(provider=provider, **config)
                
                # For Ollama, verify it's actually running
                if provider == 'ollama':
                    import asyncio
                    loop = asyncio.get_event_loop()
                    if not loop.run_until_complete(client.check_health()):
                        raise ConnectionError("Ollama server not responding")
                
                logger.info(f"Using {provider} as LLM provider")
                return client
                
            except Exception as e:
                errors.append(f"{provider}: {str(e)}")
                logger.warning(f"Failed to initialize {provider}: {e}")
                continue
        
        raise RuntimeError(f"All LLM providers failed: {errors}")
    
    @classmethod
    def get_available_providers(cls) -> list:
        """Get list of available providers"""
        return list(cls.PROVIDERS.keys())
    
    @classmethod
    def is_provider_available(cls, provider: str) -> bool:
        """Check if a provider is available"""
        provider = provider.lower()
        
        if provider not in cls.PROVIDERS:
            return False
        
        # Check if required packages are installed
        if provider == 'openai':
            try:
                import openai
                return True
            except ImportError:
                return False
        elif provider == 'groq':
            try:
                import groq
                return True
            except ImportError:
                return False
        elif provider == 'gemini':
            try:
                import google.generativeai
                return True
            except ImportError:
                return False
        elif provider == 'ollama':
            # Ollama uses HTTP API, always "available"
            return True
        
        return False


class LLMRouter:
    """
    Routes LLM requests to appropriate providers based on task type.
    Useful for using different models for different tasks.
    """
    
    def __init__(self):
        self.clients: Dict[str, BaseLLMClient] = {}
        self.routes: Dict[str, str] = {}
    
    def add_client(self, name: str, client: BaseLLMClient):
        """Add a client with a name"""
        self.clients[name] = client
    
    def set_route(self, task: str, client_name: str):
        """Set which client to use for a task"""
        if client_name not in self.clients:
            raise ValueError(f"Unknown client: {client_name}")
        self.routes[task] = client_name
    
    def get_client(self, task: str) -> BaseLLMClient:
        """Get the client for a task"""
        client_name = self.routes.get(task)
        if not client_name:
            # Return first available client as default
            if self.clients:
                return list(self.clients.values())[0]
            raise ValueError("No LLM clients configured")
        return self.clients[client_name]
    
    async def route_request(self, task: str, prompt: str, **kwargs):
        """Route a request to the appropriate client"""
        client = self.get_client(task)
        return await client.generate(prompt, **kwargs)
