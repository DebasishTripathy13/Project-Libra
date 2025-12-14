"""
ProjectLibra - OpenAI LLM Client
Integration with OpenAI GPT models (Updated for 2025 API)

Supports latest models:
- gpt-5.2 (best for coding and agentic tasks)
- gpt-5-mini (faster, cost-efficient)
- gpt-5-nano (fastest, most cost-efficient)
- gpt-4-turbo, gpt-4, gpt-3.5-turbo (legacy)
"""

import logging
from typing import Dict, Any, Optional, List
import json

from .base_client import BaseLLMClient, LLMConfig, LLMResponse

logger = logging.getLogger(__name__)

try:
    from openai import OpenAI, AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logger.warning("openai package not installed - OpenAI client disabled")


class OpenAIClient(BaseLLMClient):
    """
    OpenAI GPT client for log intelligence.
    
    Supports latest models (2025):
    - gpt-5.2: Best model for coding and agentic tasks
    - gpt-5-mini: Faster, cost-efficient for well-defined tasks
    - gpt-5-nano: Fastest, most cost-efficient
    - gpt-4-turbo: Previous generation (still supported)
    """
    
    DEFAULT_MODEL = "gpt-5.2"
    
    # Available models with descriptions
    AVAILABLE_MODELS = {
        "gpt-5.2": "Best model for coding and agentic tasks across industries",
        "gpt-5-mini": "Faster, cost-efficient version of GPT-5 for well-defined tasks",
        "gpt-5-nano": "Fastest, most cost-efficient version of GPT-5",
        "gpt-4-turbo": "Previous generation powerful model",
        "gpt-4": "Stable GPT-4 model",
        "gpt-3.5-turbo": "Fast and cost-effective legacy model"
    }
    
    def __init__(self, config: LLMConfig):
        """
        Initialize OpenAI client.
        
        Args:
            config: LLM configuration with api_key
        """
        super().__init__(config)
        
        if not OPENAI_AVAILABLE:
            raise ImportError("openai package required for OpenAIClient")
        
        if not config.api_key:
            raise ValueError("OpenAI API key required")
        
        # Initialize both sync and async clients
        self.client = OpenAI(
            api_key=config.api_key,
            timeout=config.timeout
        )
        self.async_client = AsyncOpenAI(
            api_key=config.api_key,
            timeout=config.timeout
        )
        
        self.model = config.model or self.DEFAULT_MODEL
        logger.info(f"OpenAI client initialized with model: {self.model}")
    
    async def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """
        Generate response from OpenAI using the latest responses API.
        
        Args:
            prompt: The input prompt
            **kwargs: Additional parameters (messages, max_tokens, temperature, etc.)
        
        Returns:
            LLMResponse with generated content
        """
        try:
            self._request_count += 1
            
            # Check if using chat completions or responses API
            use_responses_api = kwargs.pop('use_responses_api', False)
            
            if use_responses_api:
                # New Responses API (2025)
                response = await self._generate_with_responses_api(prompt, **kwargs)
            else:
                # Standard Chat Completions API
                response = await self._generate_with_chat_api(prompt, **kwargs)
            
            return response
            
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise
    
    async def _generate_with_chat_api(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate using Chat Completions API"""
        messages = kwargs.get('messages', [
            {"role": "system", "content": "You are a security analysis AI assistant specializing in threat detection, log analysis, and system behavior monitoring."},
            {"role": "user", "content": prompt}
        ])
        
        response = await self.async_client.chat.completions.create(
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
            provider="openai",
            tokens_used=tokens,
            finish_reason=response.choices[0].finish_reason,
            raw_response=response.model_dump() if hasattr(response, 'model_dump') else None
        )
        
        return self._parse_response(llm_response)
    
    async def _generate_with_responses_api(self, prompt: str, **kwargs) -> LLMResponse:
        """
        Generate using the new Responses API (2025).
        Better for agentic workflows and structured outputs.
        """
        import asyncio
        
        def sync_call():
            return self.client.responses.create(
                model=self.model,
                input=prompt,
                **{k: v for k, v in kwargs.items() if k in ['tools', 'tool_choice', 'response_format']}
            )
        
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, sync_call)
        
        content = response.output_text if hasattr(response, 'output_text') else str(response)
        
        llm_response = LLMResponse(
            content=content,
            model=self.model,
            provider="openai",
            tokens_used=0,
            finish_reason="stop",
            raw_response=response.model_dump() if hasattr(response, 'model_dump') else None
        )
        
        return self._parse_response(llm_response)
    
    async def analyze_log(self, log_entry: str, context: Optional[str] = None) -> LLMResponse:
        """Analyze a log entry for security implications"""
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
    
    async def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        """Have a multi-turn conversation"""
        return await self.generate("", messages=messages, **kwargs)
    
    async def generate_structured(self, 
                                   prompt: str, 
                                   schema: Dict[str, Any],
                                   **kwargs) -> LLMResponse:
        """
        Generate structured JSON output conforming to a schema.
        Uses OpenAI's Structured Outputs feature.
        """
        return await self.generate(
            prompt,
            response_format={"type": "json_schema", "json_schema": schema},
            **kwargs
        )
    
    @classmethod
    def list_models(cls) -> Dict[str, str]:
        """List available models with descriptions"""
        return cls.AVAILABLE_MODELS
