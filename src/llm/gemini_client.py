"""
ProjectLibra - Google Gemini LLM Client
Integration with Google's Gemini models (Updated for 2025 API)

Supports latest models:
- gemini-2.5-flash (balanced, 1M context window)
- gemini-2.5-flash-lite (fastest, cost-efficient)
- gemini-2.5-pro (powerful reasoning, coding)
- gemini-3-pro (most intelligent, multimodal)
"""

import logging
from typing import Dict, Any, Optional, List
import json
import asyncio

from .base_client import BaseLLMClient, LLMConfig, LLMResponse

logger = logging.getLogger(__name__)

try:
    from google import genai
    GEMINI_AVAILABLE = True
except ImportError:
    try:
        # Fallback to old import style
        import google.generativeai as genai
        GEMINI_AVAILABLE = True
    except ImportError:
        GEMINI_AVAILABLE = False
        logger.warning("google-genai package not installed - Gemini client disabled")


class GeminiClient(BaseLLMClient):
    """
    Google Gemini client for log intelligence.
    
    Supports latest models (2025):
    - gemini-3-pro: Most intelligent, best multimodal understanding
    - gemini-2.5-pro: Powerful reasoning, excels at coding
    - gemini-2.5-flash: Balanced model with 1M token context window
    - gemini-2.5-flash-lite: Fastest and most cost-efficient
    """
    
    DEFAULT_MODEL = "gemini-2.5-flash"
    
    # Available models with descriptions
    AVAILABLE_MODELS = {
        "gemini-3-pro": "Most intelligent model, best for multimodal understanding",
        "gemini-2.5-pro": "Powerful reasoning model, excels at coding and complex tasks",
        "gemini-2.5-flash": "Balanced model with 1M token context window",
        "gemini-2.5-flash-lite": "Fastest and most cost-efficient multimodal model",
        "gemini-2.5-pro-tts": "Model with native text-to-speech capabilities",
        "gemini-pro": "Legacy model (still supported)",
        "gemini-1.5-pro": "Previous generation pro model",
        "gemini-1.5-flash": "Previous generation flash model"
    }
    
    def __init__(self, config: LLMConfig):
        """
        Initialize Gemini client using new google.genai SDK.
        
        Args:
            config: LLM configuration with api_key
        """
        super().__init__(config)
        
        if not GEMINI_AVAILABLE:
            raise ImportError("google-genai package required for GeminiClient. Install with: pip install google-genai")
        
        if not config.api_key:
            raise ValueError("Gemini API key required")
        
        # Initialize with new Client API (2025)
        self.client = genai.Client(api_key=config.api_key)
        
        self.model = config.model or self.DEFAULT_MODEL
        
        # Generation config
        self.generation_config = {
            "max_output_tokens": config.max_tokens,
            "temperature": config.temperature
        }
        
        logger.info(f"Gemini client initialized with model: {self.model}")
    
    async def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """
        Generate response from Gemini using the new Client API.
        
        Args:
            prompt: The input prompt/contents
            **kwargs: Additional parameters
        
        Returns:
            LLMResponse with generated content
        """
        try:
            self._request_count += 1
            
            # Run synchronous Gemini call in executor
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, 
                self._sync_generate, 
                prompt, 
                kwargs
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            raise
    
    def _sync_generate(self, prompt: str, kwargs: dict) -> LLMResponse:
        """Synchronous generate call for use with executor"""
        # Merge generation config with kwargs
        gen_config = {**self.generation_config}
        if 'max_tokens' in kwargs:
            gen_config['max_output_tokens'] = kwargs.pop('max_tokens')
        if 'temperature' in kwargs:
            gen_config['temperature'] = kwargs.pop('temperature')
        
        # Use the new Client.models.generate_content API
        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
            config=gen_config if gen_config else None
        )
        
        content = response.text
        
        # Try to get token count if available
        tokens = 0
        if hasattr(response, 'usage_metadata'):
            tokens = getattr(response.usage_metadata, 'total_token_count', 0)
        else:
            # Rough estimate if not available
            tokens = int(len(content.split()) * 1.3)
        
        self._total_tokens += tokens
        
        llm_response = LLMResponse(
            content=content,
            model=self.model,
            provider="gemini",
            tokens_used=tokens,
            finish_reason="stop",
            raw_response={"text": content}
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
    
    async def analyze_with_context(self, 
                                    prompt: str,
                                    history: List[Dict[str, str]] = None) -> LLMResponse:
        """
        Analyze with conversation history.
        
        Args:
            prompt: Current prompt
            history: List of previous messages [{"role": "user/model", "parts": "..."}]
        """
        if history:
            # Build multi-turn conversation
            contents = history + [{"role": "user", "parts": prompt}]
            full_prompt = "\n".join([f"{m['role']}: {m['parts']}" for m in contents])
        else:
            full_prompt = prompt
        
        return await self.generate(full_prompt)
    
    async def generate_with_thinking(self, prompt: str, **kwargs) -> LLMResponse:
        """
        Generate with Gemini's thinking capabilities for complex reasoning.
        Uses models that support thinking mode for improved reasoning.
        """
        thinking_prompt = f"""Think step by step about this problem before providing your answer.

Problem:
{prompt}

First, outline your reasoning process, then provide your final answer."""
        
        return await self.generate(thinking_prompt, **kwargs)
    
    async def analyze_document(self, 
                                document_content: str, 
                                query: str) -> LLMResponse:
        """
        Analyze a document with Gemini's long context capabilities.
        Supports up to 1M tokens with gemini-2.5-flash.
        """
        prompt = f"""Analyze the following document and answer the query.

Document:
{document_content}

Query: {query}

Provide a detailed analysis based on the document content."""
        
        return await self.generate(prompt)
    
    @classmethod
    def list_models(cls) -> Dict[str, str]:
        """List available models with descriptions"""
        return cls.AVAILABLE_MODELS
