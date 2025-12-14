"""
ProjectLibra - Groq LLM Client
Ultra-fast inference via Groq Cloud
"""

import logging
from typing import Dict, Any, Optional
import json

from .base_client import BaseLLMClient, LLMConfig, LLMResponse

logger = logging.getLogger(__name__)

try:
    from groq import AsyncGroq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    logger.warning("groq package not installed - Groq client disabled")


class GroqClient(BaseLLMClient):
    """
    Groq client for ultra-fast LLM inference.
    Best for real-time analysis where speed is critical.
    
    Supports models like:
    - llama-3.1-70b-versatile
    - llama-3.1-8b-instant
    - mixtral-8x7b-32768
    - gemma-7b-it
    """
    
    DEFAULT_MODEL = "llama-3.1-70b-versatile"
    
    def __init__(self, config: LLMConfig):
        """
        Initialize Groq client.
        
        Args:
            config: LLM configuration with api_key
        """
        super().__init__(config)
        
        if not GROQ_AVAILABLE:
            raise ImportError("groq package required for GroqClient")
        
        if not config.api_key:
            raise ValueError("Groq API key required")
        
        self.client = AsyncGroq(api_key=config.api_key)
        self.model = config.model or self.DEFAULT_MODEL
        
        logger.info(f"Groq client initialized with model: {self.model}")
    
    async def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate response from Groq"""
        try:
            self._request_count += 1
            
            messages = [
                {"role": "system", "content": "You are a security analysis AI assistant. Respond in JSON format when requested."},
                {"role": "user", "content": prompt}
            ]
            
            if 'messages' in kwargs:
                messages = kwargs.pop('messages')
            
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=kwargs.get('max_tokens', self.config.max_tokens),
                temperature=kwargs.get('temperature', self.config.temperature)
            )
            
            content = response.choices[0].message.content
            tokens = response.usage.total_tokens if response.usage else 0
            self._total_tokens += tokens
            
            llm_response = LLMResponse(
                content=content,
                model=self.model,
                provider="groq",
                tokens_used=tokens,
                finish_reason=response.choices[0].finish_reason,
                raw_response=response.model_dump() if hasattr(response, 'model_dump') else None
            )
            
            return self._parse_response(llm_response)
            
        except Exception as e:
            logger.error(f"Groq API error: {e}")
            raise
    
    async def analyze_log(self, log_entry: str, context: Optional[str] = None) -> LLMResponse:
        """Analyze a log entry"""
        prompt = self._build_log_analysis_prompt(log_entry, context)
        return await self.generate(prompt)
    
    async def classify_threat(self,
                               event_data: Dict[str, Any],
                               baseline: Optional[Dict[str, Any]] = None) -> LLMResponse:
        """Classify threat level of an event"""
        prompt = self._build_threat_classification_prompt(event_data, baseline)
        return await self.generate(prompt)
    
    async def explain_anomaly(self,
                               anomaly_data: Dict[str, Any],
                               baseline: Dict[str, Any]) -> LLMResponse:
        """Explain why an event is anomalous"""
        prompt = self._build_anomaly_explanation_prompt(anomaly_data, baseline)
        return await self.generate(prompt)
