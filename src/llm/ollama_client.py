"""
ProjectLibra - Ollama LLM Client
Local LLM integration via Ollama for privacy-preserving analysis
"""

import logging
from typing import Dict, Any, Optional
import json
import aiohttp

from .base_client import BaseLLMClient, LLMConfig, LLMResponse

logger = logging.getLogger(__name__)


class OllamaClient(BaseLLMClient):
    """
    Ollama client for local LLM inference.
    Privacy-first option - all data stays on the local machine.
    
    Supports models like:
    - llama2, llama2:13b, llama2:70b
    - mistral, mixtral
    - codellama
    - neural-chat
    - starling-lm
    """
    
    DEFAULT_BASE_URL = "http://localhost:11434"
    DEFAULT_MODEL = "llama2"
    
    def __init__(self, config: LLMConfig):
        """
        Initialize Ollama client.
        
        Args:
            config: LLM configuration with optional base_url
        """
        super().__init__(config)
        
        self.base_url = config.base_url or self.DEFAULT_BASE_URL
        self.model = config.model or self.DEFAULT_MODEL
        
        logger.info(f"Ollama client initialized: {self.base_url} with model: {self.model}")
    
    async def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate response from Ollama"""
        try:
            self._request_count += 1
            
            url = f"{self.base_url}/api/generate"
            
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": kwargs.get('temperature', self.config.temperature),
                    "num_predict": kwargs.get('max_tokens', self.config.max_tokens)
                }
            }
            
            # Add system prompt if provided
            if 'system' in kwargs:
                payload['system'] = kwargs['system']
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(f"Ollama API error: {response.status} - {error_text}")
                    
                    data = await response.json()
            
            content = data.get('response', '')
            
            # Ollama doesn't return token counts in the same way
            eval_count = data.get('eval_count', 0)
            self._total_tokens += eval_count
            
            llm_response = LLMResponse(
                content=content,
                model=self.model,
                provider="ollama",
                tokens_used=eval_count,
                finish_reason="stop" if data.get('done', False) else "length",
                raw_response=data
            )
            
            return self._parse_response(llm_response)
            
        except aiohttp.ClientError as e:
            logger.error(f"Ollama connection error: {e}")
            raise
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            raise
    
    async def analyze_log(self, log_entry: str, context: Optional[str] = None) -> LLMResponse:
        """Analyze a log entry"""
        prompt = self._build_log_analysis_prompt(log_entry, context)
        return await self.generate(
            prompt,
            system="You are a security analyst AI. Respond only in valid JSON format."
        )
    
    async def classify_threat(self,
                               event_data: Dict[str, Any],
                               baseline: Optional[Dict[str, Any]] = None) -> LLMResponse:
        """Classify threat level of an event"""
        prompt = self._build_threat_classification_prompt(event_data, baseline)
        return await self.generate(
            prompt,
            system="You are a threat intelligence AI. Respond only in valid JSON format."
        )
    
    async def explain_anomaly(self,
                               anomaly_data: Dict[str, Any],
                               baseline: Dict[str, Any]) -> LLMResponse:
        """Explain why an event is anomalous"""
        prompt = self._build_anomaly_explanation_prompt(anomaly_data, baseline)
        return await self.generate(
            prompt,
            system="You are a security analyst AI. Respond only in valid JSON format."
        )
    
    async def check_health(self) -> bool:
        """Check if Ollama server is healthy"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/api/tags",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    return response.status == 200
        except:
            return False
    
    async def list_models(self) -> list:
        """List available models"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/api/tags",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return [m['name'] for m in data.get('models', [])]
        except Exception as e:
            logger.error(f"Error listing models: {e}")
        return []
    
    async def pull_model(self, model_name: str) -> bool:
        """Pull a model from Ollama library"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/api/pull",
                    json={"name": model_name},
                    timeout=aiohttp.ClientTimeout(total=3600)  # Long timeout for downloads
                ) as response:
                    return response.status == 200
        except Exception as e:
            logger.error(f"Error pulling model: {e}")
            return False
