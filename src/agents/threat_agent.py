"""
Threat Reasoning Agent for AI-Powered Analysis.

Uses LLM capabilities for sophisticated threat analysis,
explanation generation, and remediation recommendations.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
import json
import logging

from .base_agent import BaseAgent, AgentMessage, AgentState, MessagePriority
from ..ml.feature_extractor import FeatureSet
from ..ml.anomaly_detector import AnomalyResult, AnomalySeverity
from ..ml.pattern_detector import PatternMatch
from ..llm import BaseLLMClient, LLMFactory, LLMConfig


@dataclass
class ThreatAssessment:
    """Comprehensive threat assessment."""
    
    assessment_id: str
    timestamp: datetime
    threat_level: str  # 'none', 'low', 'medium', 'high', 'critical'
    confidence: float
    summary: str
    detailed_analysis: str
    indicators: List[str]
    affected_assets: List[str]
    attack_techniques: List[str]
    recommended_actions: List[str]
    related_anomalies: List[AnomalyResult]
    related_patterns: List[PatternMatch]
    llm_reasoning: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'assessment_id': self.assessment_id,
            'timestamp': self.timestamp.isoformat(),
            'threat_level': self.threat_level,
            'confidence': self.confidence,
            'summary': self.summary,
            'detailed_analysis': self.detailed_analysis,
            'indicators': self.indicators,
            'affected_assets': self.affected_assets,
            'attack_techniques': self.attack_techniques,
            'recommended_actions': self.recommended_actions,
            'anomaly_count': len(self.related_anomalies),
            'pattern_count': len(self.related_patterns),
            'llm_reasoning': self.llm_reasoning,
        }


class ThreatReasoningAgent(BaseAgent):
    """
    Agent for AI-powered threat reasoning and analysis.
    
    Capabilities:
    - Deep analysis of anomalies and patterns
    - Natural language threat explanations
    - Attack technique identification (MITRE ATT&CK)
    - Remediation recommendations
    - Context-aware reasoning using LLM
    """
    
    # Message types
    MSG_THREAT_ASSESSMENT = 'threat.assessment'
    MSG_THREAT_EXPLANATION = 'threat.explanation'
    MSG_REMEDIATION_GUIDANCE = 'threat.remediation'
    
    def __init__(
        self,
        llm_client: Optional[BaseLLMClient] = None,
        llm_config: Optional[LLMConfig] = None,
        analysis_threshold: float = 0.5,
        enable_llm_analysis: bool = True,
        message_handler: Optional[Callable[[AgentMessage], None]] = None,
    ):
        """
        Initialize threat reasoning agent.
        
        Args:
            llm_client: Pre-configured LLM client
            llm_config: LLM configuration (used if client not provided)
            analysis_threshold: Minimum anomaly score to trigger analysis
            enable_llm_analysis: Whether to use LLM for enhanced analysis
            message_handler: Callback for outbound messages
        """
        super().__init__(
            name='ThreatReasoningAgent',
            description='AI-powered threat analysis and reasoning',
            message_handler=message_handler,
        )
        
        self._llm_client = llm_client
        self._llm_config = llm_config
        self._enable_llm = enable_llm_analysis
        self.analysis_threshold = analysis_threshold
        
        # Assessment tracking
        self._assessment_counter = 0
        self._recent_assessments: List[ThreatAssessment] = []
        self._max_assessments = 100
        
        # Analysis queue
        self._analysis_queue: List[Dict[str, Any]] = []
        self._max_queue_size = 50
    
    async def _initialize(self) -> None:
        """Initialize agent."""
        self.logger.info("Initializing threat reasoning agent...")
        
        # Initialize LLM client if not provided
        if self._enable_llm and not self._llm_client:
            try:
                if self._llm_config:
                    self._llm_client = LLMFactory.create(self._llm_config)
                    self.logger.info(f"LLM client initialized: {self._llm_config.provider}")
                else:
                    # Try to create default (Ollama) client
                    try:
                        self._llm_config = LLMConfig(provider='ollama', model='llama2')
                        self._llm_client = LLMFactory.create(self._llm_config)
                        self.logger.info("Default Ollama LLM client initialized")
                    except Exception:
                        self.logger.warning("LLM client not available, using rule-based analysis")
                        self._enable_llm = False
            except Exception as e:
                self.logger.warning(f"Failed to initialize LLM: {e}")
                self._enable_llm = False
        
        # Subscribe to relevant messages
        self.subscribe('anomaly.detected')
        self.subscribe('pattern.matched')
        self.subscribe('correlation.found')
        self.subscribe('correlation.attack_chain')
        self.subscribe('request.analyze')
    
    async def _cleanup(self) -> None:
        """Clean up resources."""
        self.logger.info("Cleaning up threat reasoning agent...")
    
    async def _handle_message(self, message: AgentMessage) -> None:
        """Handle incoming messages."""
        if message.message_type == 'anomaly.detected':
            await self._handle_anomaly(message.payload)
        
        elif message.message_type == 'pattern.matched':
            await self._handle_pattern(message.payload)
        
        elif message.message_type == 'correlation.found':
            await self._handle_correlation(message.payload)
        
        elif message.message_type == 'correlation.attack_chain':
            await self._handle_attack_chain(message.payload)
        
        elif message.message_type == 'request.analyze':
            await self._handle_analysis_request(message.payload)
    
    async def _periodic_task(self) -> None:
        """Process analysis queue."""
        if self._analysis_queue:
            item = self._analysis_queue.pop(0)
            await self._perform_analysis(item)
    
    async def _handle_anomaly(self, anomaly: AnomalyResult) -> None:
        """Process anomaly for threat assessment."""
        if anomaly.anomaly_score >= self.analysis_threshold:
            self._queue_analysis({
                'type': 'anomaly',
                'data': anomaly,
                'priority': self._get_priority(anomaly.severity),
            })
    
    async def _handle_pattern(self, pattern: PatternMatch) -> None:
        """Process pattern match."""
        if pattern.severity >= self.analysis_threshold:
            self._queue_analysis({
                'type': 'pattern',
                'data': pattern,
                'priority': MessagePriority.HIGH,
            })
    
    async def _handle_correlation(self, correlation: Dict[str, Any]) -> None:
        """Process correlation event."""
        if correlation.get('correlation_score', 0) >= self.analysis_threshold:
            self._queue_analysis({
                'type': 'correlation',
                'data': correlation,
                'priority': MessagePriority.NORMAL,
            })
    
    async def _handle_attack_chain(self, chain: Dict[str, Any]) -> None:
        """Process attack chain detection."""
        self._queue_analysis({
            'type': 'attack_chain',
            'data': chain,
            'priority': MessagePriority.CRITICAL,
        })
    
    async def _handle_analysis_request(self, request: Dict[str, Any]) -> None:
        """Handle explicit analysis request."""
        self._queue_analysis({
            'type': 'request',
            'data': request,
            'priority': MessagePriority.HIGH,
        })
    
    def _queue_analysis(self, item: Dict[str, Any]) -> None:
        """Add item to analysis queue."""
        if len(self._analysis_queue) >= self._max_queue_size:
            # Remove lowest priority item
            self._analysis_queue.sort(key=lambda x: x.get('priority', MessagePriority.NORMAL).value)
            self._analysis_queue.pop(0)
        
        self._analysis_queue.append(item)
        # Sort by priority (highest first)
        self._analysis_queue.sort(key=lambda x: x.get('priority', MessagePriority.NORMAL).value, reverse=True)
    
    def _get_priority(self, severity: AnomalySeverity) -> MessagePriority:
        """Map severity to message priority."""
        mapping = {
            AnomalySeverity.LOW: MessagePriority.LOW,
            AnomalySeverity.MEDIUM: MessagePriority.NORMAL,
            AnomalySeverity.HIGH: MessagePriority.HIGH,
            AnomalySeverity.CRITICAL: MessagePriority.CRITICAL,
        }
        return mapping.get(severity, MessagePriority.NORMAL)
    
    async def _perform_analysis(self, item: Dict[str, Any]) -> None:
        """Perform threat analysis."""
        analysis_type = item['type']
        data = item['data']
        
        try:
            if analysis_type == 'anomaly':
                assessment = await self._analyze_anomaly(data)
            elif analysis_type == 'pattern':
                assessment = await self._analyze_pattern(data)
            elif analysis_type == 'correlation':
                assessment = await self._analyze_correlation(data)
            elif analysis_type == 'attack_chain':
                assessment = await self._analyze_attack_chain(data)
            else:
                assessment = await self._generic_analysis(data)
            
            # Store assessment
            self._recent_assessments.append(assessment)
            if len(self._recent_assessments) > self._max_assessments:
                self._recent_assessments.pop(0)
            
            # Broadcast assessment
            priority = item.get('priority', MessagePriority.NORMAL)
            self.broadcast(
                self.MSG_THREAT_ASSESSMENT,
                assessment.to_dict(),
                priority=priority,
            )
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
    
    async def _analyze_anomaly(self, anomaly: AnomalyResult) -> ThreatAssessment:
        """Analyze anomaly detection result."""
        self._assessment_counter += 1
        
        # Rule-based analysis
        threat_level = self._score_to_threat_level(anomaly.anomaly_score)
        indicators = anomaly.reasons.copy()
        affected_assets = []
        techniques = []
        
        # Source-specific analysis
        if anomaly.source_type == 'log':
            techniques.extend(['T1078 - Valid Accounts', 'T1110 - Brute Force'])
        elif anomaly.source_type == 'process':
            techniques.extend(['T1059 - Command Line', 'T1106 - Native API'])
            affected_assets.append('Local System')
        elif anomaly.source_type == 'network':
            techniques.extend(['T1071 - Application Layer Protocol'])
        
        # LLM enhanced analysis
        llm_reasoning = None
        if self._enable_llm and self._llm_client and anomaly.anomaly_score >= 0.7:
            llm_reasoning = await self._get_llm_analysis(anomaly)
            if llm_reasoning:
                # Parse LLM response for additional insights
                try:
                    if 'CRITICAL' in llm_reasoning.upper():
                        threat_level = 'critical'
                    elif 'HIGH' in llm_reasoning.upper():
                        threat_level = max(threat_level, 'high', key=['none', 'low', 'medium', 'high', 'critical'].index)
                except:
                    pass
        
        return ThreatAssessment(
            assessment_id=f"ASSESS-{self._assessment_counter:06d}",
            timestamp=datetime.now(),
            threat_level=threat_level,
            confidence=min(anomaly.anomaly_score + 0.1, 1.0),
            summary=f"Anomaly detected in {anomaly.source_type} data",
            detailed_analysis=self._generate_detailed_analysis(anomaly),
            indicators=indicators,
            affected_assets=affected_assets,
            attack_techniques=techniques,
            recommended_actions=self._generate_recommendations(anomaly),
            related_anomalies=[anomaly],
            related_patterns=[],
            llm_reasoning=llm_reasoning,
        )
    
    async def _analyze_pattern(self, pattern: PatternMatch) -> ThreatAssessment:
        """Analyze pattern match."""
        self._assessment_counter += 1
        
        return ThreatAssessment(
            assessment_id=f"ASSESS-{self._assessment_counter:06d}",
            timestamp=datetime.now(),
            threat_level=self._score_to_threat_level(pattern.severity),
            confidence=pattern.confidence,
            summary=f"Pattern detected: {pattern.pattern_name}",
            detailed_analysis=pattern.description,
            indicators=pattern.evidence,
            affected_assets=[],
            attack_techniques=pattern.mitre_techniques,
            recommended_actions=pattern.recommended_actions,
            related_anomalies=[],
            related_patterns=[pattern],
        )
    
    async def _analyze_correlation(self, correlation: Dict[str, Any]) -> ThreatAssessment:
        """Analyze correlated events."""
        self._assessment_counter += 1
        
        score = correlation.get('correlation_score', 0.5)
        
        return ThreatAssessment(
            assessment_id=f"ASSESS-{self._assessment_counter:06d}",
            timestamp=datetime.now(),
            threat_level=self._score_to_threat_level(score),
            confidence=score,
            summary=f"Event correlation: {correlation.get('correlation_type', 'unknown')}",
            detailed_analysis=correlation.get('description', ''),
            indicators=[f"Correlated events: {correlation.get('event_count', 0)}"],
            affected_assets=list(correlation.get('entities', [])),
            attack_techniques=[],
            recommended_actions=['Review correlated events', 'Check for ongoing attack'],
            related_anomalies=[],
            related_patterns=[],
        )
    
    async def _analyze_attack_chain(self, chain: Dict[str, Any]) -> ThreatAssessment:
        """Analyze attack chain detection."""
        self._assessment_counter += 1
        
        return ThreatAssessment(
            assessment_id=f"ASSESS-{self._assessment_counter:06d}",
            timestamp=datetime.now(),
            threat_level='high',
            confidence=chain.get('correlation_score', 0.7),
            summary=f"Attack chain detected: {chain.get('description', 'Unknown')}",
            detailed_analysis="Multiple attack stages detected in sequence, indicating an active intrusion",
            indicators=[chain.get('description', '')],
            affected_assets=list(chain.get('entities', [])),
            attack_techniques=['Multi-stage attack'],
            recommended_actions=[
                'Immediately isolate affected systems',
                'Initiate incident response procedures',
                'Capture forensic evidence',
                'Review all related events',
            ],
            related_anomalies=[],
            related_patterns=[],
        )
    
    async def _generic_analysis(self, data: Dict[str, Any]) -> ThreatAssessment:
        """Generic analysis for arbitrary data."""
        self._assessment_counter += 1
        
        return ThreatAssessment(
            assessment_id=f"ASSESS-{self._assessment_counter:06d}",
            timestamp=datetime.now(),
            threat_level='low',
            confidence=0.5,
            summary="Generic security analysis",
            detailed_analysis=str(data),
            indicators=[],
            affected_assets=[],
            attack_techniques=[],
            recommended_actions=['Review the event details'],
            related_anomalies=[],
            related_patterns=[],
        )
    
    async def _get_llm_analysis(self, anomaly: AnomalyResult) -> Optional[str]:
        """Get LLM-powered analysis."""
        if not self._llm_client:
            return None
        
        try:
            # Prepare prompt
            prompt = f"""Analyze this security anomaly and provide insights:

Source Type: {anomaly.source_type}
Anomaly Score: {anomaly.anomaly_score:.2f}
Severity: {anomaly.severity.value}
Reasons: {', '.join(anomaly.reasons)}

Feature Contributions:
{json.dumps(anomaly.feature_contributions, indent=2)}

Provide:
1. Threat assessment (CRITICAL/HIGH/MEDIUM/LOW)
2. Possible attack techniques (MITRE ATT&CK)
3. Recommended immediate actions
4. Additional indicators to look for

Keep response concise and actionable."""

            response = await asyncio.to_thread(
                self._llm_client.analyze_log,
                prompt
            )
            
            return response.text if response else None
            
        except Exception as e:
            self.logger.error(f"LLM analysis failed: {e}")
            return None
    
    def _score_to_threat_level(self, score: float) -> str:
        """Convert numeric score to threat level."""
        if score >= 0.9:
            return 'critical'
        elif score >= 0.7:
            return 'high'
        elif score >= 0.5:
            return 'medium'
        elif score >= 0.3:
            return 'low'
        return 'none'
    
    def _generate_detailed_analysis(self, anomaly: AnomalyResult) -> str:
        """Generate detailed analysis text."""
        lines = [
            f"Anomaly detected in {anomaly.source_type} at {anomaly.timestamp.isoformat()}",
            f"Overall anomaly score: {anomaly.anomaly_score:.2f} ({anomaly.severity.value} severity)",
            "",
            "Contributing factors:",
        ]
        
        for feature, contribution in sorted(
            anomaly.feature_contributions.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]:
            lines.append(f"  - {feature}: {contribution:.2f}")
        
        if anomaly.reasons:
            lines.extend(["", "Detection reasons:"])
            for reason in anomaly.reasons:
                lines.append(f"  - {reason}")
        
        return '\n'.join(lines)
    
    def _generate_recommendations(self, anomaly: AnomalyResult) -> List[str]:
        """Generate recommended actions."""
        recommendations = []
        
        if anomaly.severity == AnomalySeverity.CRITICAL:
            recommendations.extend([
                "Immediately isolate affected system",
                "Alert security team",
                "Capture forensic evidence",
            ])
        elif anomaly.severity == AnomalySeverity.HIGH:
            recommendations.extend([
                "Investigate anomaly immediately",
                "Check for related events",
                "Consider isolation if attack confirmed",
            ])
        else:
            recommendations.extend([
                "Monitor for additional anomalies",
                "Review system logs",
            ])
        
        # Source-specific recommendations
        if anomaly.source_type == 'log':
            recommendations.append("Check authentication logs")
        elif anomaly.source_type == 'process':
            recommendations.append("Review running processes")
        elif anomaly.source_type == 'network':
            recommendations.append("Analyze network traffic")
        
        return recommendations
    
    def get_recent_assessments(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent threat assessments."""
        return [a.to_dict() for a in self._recent_assessments[-limit:]]
