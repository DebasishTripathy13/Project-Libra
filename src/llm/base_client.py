"""
ProjectLibra - Base LLM Client
Abstract base class for LLM integrations
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)


class LLMProvider(Enum):
    """Supported LLM providers"""
    OPENAI = "openai"
    OLLAMA = "ollama"
    GROQ = "groq"
    GEMINI = "gemini"


@dataclass
class LLMConfig:
    """Configuration for LLM client"""
    provider: str
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.7
    timeout: int = 60
    retry_attempts: int = 3
    extra_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    """Standardized LLM response"""
    content: str
    model: str
    provider: str
    tokens_used: int = 0
    finish_reason: str = "stop"
    raw_response: Optional[Dict[str, Any]] = None
    
    # Parsed fields for structured responses
    confidence: float = 0.0
    reasoning: str = ""
    classification: str = ""
    structured_data: Optional[Dict[str, Any]] = None
    
    def parse_json(self) -> Optional[Dict[str, Any]]:
        """Try to parse content as JSON"""
        try:
            # Try to find JSON in the response
            content = self.content
            
            # Look for JSON blocks
            if '```json' in content:
                start = content.find('```json') + 7
                end = content.find('```', start)
                content = content[start:end].strip()
            elif '```' in content:
                start = content.find('```') + 3
                end = content.find('```', start)
                content = content[start:end].strip()
            
            return json.loads(content)
        except json.JSONDecodeError:
            return None


class BaseLLMClient(ABC):
    """
    Abstract base class for LLM clients.
    All LLM integrations should inherit from this class.
    """
    
    def __init__(self, config: LLMConfig):
        """
        Initialize the LLM client.
        
        Args:
            config: LLM configuration
        """
        self.config = config
        self.model = config.model
        self.provider = config.provider
        self._request_count = 0
        self._total_tokens = 0
    
    @abstractmethod
    async def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """
        Generate a response from the LLM.
        
        Args:
            prompt: The prompt to send to the LLM
            **kwargs: Additional parameters
            
        Returns:
            LLMResponse object
        """
        pass
    
    @abstractmethod
    async def analyze_log(self, log_entry: str, context: Optional[str] = None) -> LLMResponse:
        """
        Analyze a log entry using the LLM.
        
        Args:
            log_entry: The log entry to analyze
            context: Additional context
            
        Returns:
            LLMResponse with analysis
        """
        pass
    
    @abstractmethod
    async def classify_threat(self, 
                              event_data: Dict[str, Any],
                              baseline: Optional[Dict[str, Any]] = None) -> LLMResponse:
        """
        Classify the threat level of an event.
        
        Args:
            event_data: Event data to classify
            baseline: Behavioral baseline for comparison
            
        Returns:
            LLMResponse with threat classification
        """
        pass
    
    @abstractmethod
    async def explain_anomaly(self,
                               anomaly_data: Dict[str, Any],
                               baseline: Dict[str, Any]) -> LLMResponse:
        """
        Explain why an event is anomalous.
        
        Args:
            anomaly_data: The anomalous event data
            baseline: Normal behavioral baseline
            
        Returns:
            LLMResponse with explanation
        """
        pass
    
    async def correlate_events(self, events: List[Dict[str, Any]]) -> LLMResponse:
        """
        Find correlations between multiple events.
        
        Args:
            events: List of events to correlate
            
        Returns:
            LLMResponse with correlation analysis
        """
        prompt = self._build_correlation_prompt(events)
        return await self.generate(prompt)
    
    def _build_log_analysis_prompt(self, log_entry: str, context: Optional[str] = None) -> str:
        """Build prompt for log analysis"""
        prompt = f"""You are a security analyst AI. Analyze the following log entry and provide:
1. Classification (normal, suspicious, malicious, error)
2. Severity (info, low, medium, high, critical)
3. Brief explanation
4. Recommended actions (if any)

Log Entry:
{log_entry}
"""
        if context:
            prompt += f"\nAdditional Context:\n{context}\n"
        
        prompt += """
Respond in JSON format:
{
    "classification": "...",
    "severity": "...",
    "explanation": "...",
    "indicators": [...],
    "recommended_actions": [...]
}"""
        return prompt
    
    def _build_threat_classification_prompt(self,
                                             event_data: Dict[str, Any],
                                             baseline: Optional[Dict[str, Any]] = None) -> str:
        """Build prompt for threat classification"""
        prompt = f"""You are a threat intelligence AI. Analyze the following security event and classify its threat level.

Event Data:
{json.dumps(event_data, indent=2, default=str)}
"""
        if baseline:
            prompt += f"""
Behavioral Baseline (normal patterns):
{json.dumps(baseline, indent=2, default=str)}
"""
        
        prompt += """
Provide your analysis in JSON format:
{
    "threat_level": "none|low|medium|high|critical",
    "confidence": 0.0-1.0,
    "threat_type": "...",
    "indicators_of_compromise": [...],
    "attack_technique": "MITRE ATT&CK technique if applicable",
    "reasoning": "...",
    "recommended_response": [...]
}"""
        return prompt
    
    def _build_anomaly_explanation_prompt(self,
                                          anomaly_data: Dict[str, Any],
                                          baseline: Dict[str, Any]) -> str:
        """Build prompt for anomaly explanation"""
        return f"""You are a security analyst AI. Explain why the following event is anomalous compared to the baseline.

Anomalous Event:
{json.dumps(anomaly_data, indent=2, default=str)}

Normal Baseline:
{json.dumps(baseline, indent=2, default=str)}

Provide your explanation in JSON format:
{{
    "is_anomaly": true/false,
    "anomaly_score": 0.0-1.0,
    "deviations": [
        {{"field": "...", "expected": "...", "actual": "...", "significance": "..."}}
    ],
    "possible_causes": [...],
    "risk_assessment": "...",
    "investigation_steps": [...]
}}"""
    
    def _build_correlation_prompt(self, events: List[Dict[str, Any]]) -> str:
        """Build prompt for event correlation"""
        return f"""You are a security analyst AI. Analyze the following events and identify any correlations or attack patterns.

Events:
{json.dumps(events, indent=2, default=str)}

Look for:
1. Temporal correlations (events happening in sequence)
2. Causal relationships (one event triggering another)
3. Attack chain patterns (reconnaissance → exploitation → persistence)
4. Lateral movement indicators

Provide your analysis in JSON format:
{{
    "correlations_found": true/false,
    "correlation_groups": [
        {{
            "event_ids": [...],
            "relationship": "...",
            "confidence": 0.0-1.0
        }}
    ],
    "attack_chain": {{
        "detected": true/false,
        "stages": [...],
        "technique": "..."
    }},
    "summary": "...",
    "recommended_actions": [...]
}}"""
    
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics"""
        return {
            'provider': self.provider,
            'model': self.model,
            'request_count': self._request_count,
            'total_tokens': self._total_tokens
        }
    
    def _parse_response(self, response: LLMResponse) -> LLMResponse:
        """Parse and enrich LLM response"""
        parsed = response.parse_json()
        
        if parsed:
            response.structured_data = parsed
            response.confidence = parsed.get('confidence', 0.0)
            response.reasoning = parsed.get('reasoning', parsed.get('explanation', ''))
            response.classification = parsed.get('classification', 
                                                  parsed.get('threat_level', ''))
        
        return response
