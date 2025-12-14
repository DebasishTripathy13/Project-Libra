"""
Correlation Agent for Event Analysis.

Correlates security events across different sources to
identify patterns and potential multi-stage attacks.
"""

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import logging

from .base_agent import BaseAgent, AgentMessage, AgentState, MessagePriority
from ..ml.feature_extractor import FeatureSet
from ..ml.anomaly_detector import AnomalyResult


@dataclass
class CorrelatedEvent:
    """A group of correlated security events."""
    
    correlation_id: str
    events: List[FeatureSet]
    anomalies: List[AnomalyResult]
    created_at: datetime
    updated_at: datetime
    correlation_score: float  # 0.0 to 1.0
    correlation_type: str  # 'temporal', 'source', 'entity', 'pattern'
    entities: Set[str] = field(default_factory=set)  # IPs, users, processes
    description: str = ''
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'correlation_id': self.correlation_id,
            'event_count': len(self.events),
            'anomaly_count': len(self.anomalies),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'correlation_score': self.correlation_score,
            'correlation_type': self.correlation_type,
            'entities': list(self.entities),
            'description': self.description,
        }


class CorrelationAgent(BaseAgent):
    """
    Agent responsible for correlating security events.
    
    Capabilities:
    - Temporal correlation (events close in time)
    - Entity correlation (same IP, user, process)
    - Pattern correlation (related attack patterns)
    - Attack chain detection
    """
    
    # Message types
    MSG_CORRELATION_FOUND = 'correlation.found'
    MSG_ATTACK_CHAIN = 'correlation.attack_chain'
    MSG_CORRELATION_UPDATE = 'correlation.update'
    
    def __init__(
        self,
        correlation_window: timedelta = timedelta(minutes=5),
        min_correlation_score: float = 0.5,
        max_events_tracked: int = 10000,
        message_handler: Optional[Callable[[AgentMessage], None]] = None,
    ):
        """
        Initialize correlation agent.
        
        Args:
            correlation_window: Time window for temporal correlation
            min_correlation_score: Minimum score to report correlation
            max_events_tracked: Maximum events to keep in memory
            message_handler: Callback for outbound messages
        """
        super().__init__(
            name='CorrelationAgent',
            description='Correlates security events across sources',
            message_handler=message_handler,
        )
        
        self.correlation_window = correlation_window
        self.min_correlation_score = min_correlation_score
        self.max_events_tracked = max_events_tracked
        
        # Event storage
        self._events: List[Tuple[datetime, FeatureSet]] = []
        self._anomalies: List[Tuple[datetime, AnomalyResult]] = []
        
        # Active correlations
        self._correlations: Dict[str, CorrelatedEvent] = {}
        self._correlation_counter = 0
        
        # Entity tracking
        self._ip_events: Dict[str, List[datetime]] = defaultdict(list)
        self._user_events: Dict[str, List[datetime]] = defaultdict(list)
        self._process_events: Dict[str, List[datetime]] = defaultdict(list)
        
        # Attack chain patterns
        self._attack_chains = self._define_attack_chains()
    
    async def _initialize(self) -> None:
        """Initialize agent."""
        self.logger.info("Initializing correlation agent...")
        
        # Subscribe to observation events
        self.subscribe('observation.feature_set')
        self.subscribe('anomaly.detected')
        self.subscribe('threat.assessment')
    
    async def _cleanup(self) -> None:
        """Clean up resources."""
        self.logger.info("Cleaning up correlation agent...")
        self._events.clear()
        self._anomalies.clear()
        self._correlations.clear()
    
    async def _handle_message(self, message: AgentMessage) -> None:
        """Handle incoming messages."""
        if message.message_type == 'observation.feature_set':
            await self._handle_feature_set(message.payload)
        
        elif message.message_type == 'anomaly.detected':
            await self._handle_anomaly(message.payload)
        
        elif message.message_type == 'threat.assessment':
            await self._handle_threat(message.payload)
    
    async def _periodic_task(self) -> None:
        """Periodic correlation analysis."""
        # Clean up old events
        await self._cleanup_old_events()
        
        # Check for attack chains
        chains = await self._detect_attack_chains()
        for chain in chains:
            self.broadcast(
                self.MSG_ATTACK_CHAIN,
                chain.to_dict(),
                priority=MessagePriority.HIGH,
            )
    
    async def _handle_feature_set(self, feature_set: FeatureSet) -> None:
        """Process new feature set."""
        timestamp = feature_set.timestamp
        
        # Store event
        self._events.append((timestamp, feature_set))
        
        # Trim if needed
        if len(self._events) > self.max_events_tracked:
            self._events = self._events[-self.max_events_tracked:]
        
        # Extract entities and track
        entities = self._extract_entities(feature_set)
        for entity_type, entity_value in entities:
            if entity_type == 'ip':
                self._ip_events[entity_value].append(timestamp)
            elif entity_type == 'user':
                self._user_events[entity_value].append(timestamp)
            elif entity_type == 'process':
                self._process_events[entity_value].append(timestamp)
        
        # Check for correlations
        correlations = await self._find_correlations(feature_set, timestamp)
        
        for corr in correlations:
            if corr.correlation_score >= self.min_correlation_score:
                self.broadcast(
                    self.MSG_CORRELATION_FOUND,
                    corr.to_dict(),
                    priority=MessagePriority.NORMAL,
                )
    
    async def _handle_anomaly(self, anomaly: AnomalyResult) -> None:
        """Process anomaly detection result."""
        self._anomalies.append((anomaly.timestamp, anomaly))
        
        # Trim if needed
        if len(self._anomalies) > self.max_events_tracked:
            self._anomalies = self._anomalies[-self.max_events_tracked:]
        
        # Check for correlated anomalies
        if anomaly.is_anomaly:
            await self._correlate_anomaly(anomaly)
    
    async def _handle_threat(self, threat: Dict[str, Any]) -> None:
        """Process threat assessment."""
        # Update relevant correlations with threat info
        pass
    
    async def _find_correlations(
        self,
        feature_set: FeatureSet,
        timestamp: datetime,
    ) -> List[CorrelatedEvent]:
        """Find correlations for a new event."""
        correlations = []
        
        # Temporal correlation
        temporal = await self._temporal_correlation(feature_set, timestamp)
        if temporal:
            correlations.append(temporal)
        
        # Entity correlation
        entities = self._extract_entities(feature_set)
        for entity_type, entity_value in entities:
            entity_corr = await self._entity_correlation(
                entity_type, entity_value, feature_set, timestamp
            )
            if entity_corr:
                correlations.append(entity_corr)
        
        return correlations
    
    async def _temporal_correlation(
        self,
        feature_set: FeatureSet,
        timestamp: datetime,
    ) -> Optional[CorrelatedEvent]:
        """Find temporally correlated events."""
        cutoff = timestamp - self.correlation_window
        
        # Get recent events of different types
        recent_events = [
            fs for ts, fs in self._events
            if ts >= cutoff and fs.source_type != feature_set.source_type
        ]
        
        if len(recent_events) < 2:
            return None
        
        # Check for suspicious pattern combinations
        source_types = {fs.source_type for fs in recent_events}
        source_types.add(feature_set.source_type)
        
        # Multiple source types active = potentially interesting
        if len(source_types) >= 3:
            self._correlation_counter += 1
            return CorrelatedEvent(
                correlation_id=f"CORR-{self._correlation_counter:06d}",
                events=recent_events + [feature_set],
                anomalies=[],
                created_at=timestamp,
                updated_at=timestamp,
                correlation_score=0.3 + len(source_types) * 0.1,
                correlation_type='temporal',
                description=f"Activity across {len(source_types)} source types in {self.correlation_window}",
            )
        
        return None
    
    async def _entity_correlation(
        self,
        entity_type: str,
        entity_value: str,
        feature_set: FeatureSet,
        timestamp: datetime,
    ) -> Optional[CorrelatedEvent]:
        """Find events correlated by entity."""
        cutoff = timestamp - self.correlation_window
        
        # Get event timestamps for this entity
        if entity_type == 'ip':
            event_times = self._ip_events.get(entity_value, [])
        elif entity_type == 'user':
            event_times = self._user_events.get(entity_value, [])
        elif entity_type == 'process':
            event_times = self._process_events.get(entity_value, [])
        else:
            return None
        
        recent_times = [t for t in event_times if t >= cutoff]
        
        # High frequency from same entity is suspicious
        if len(recent_times) >= 5:
            self._correlation_counter += 1
            
            # Calculate frequency
            time_span = (timestamp - min(recent_times)).total_seconds()
            frequency = len(recent_times) / max(time_span, 1) * 60  # events per minute
            
            return CorrelatedEvent(
                correlation_id=f"CORR-{self._correlation_counter:06d}",
                events=[feature_set],
                anomalies=[],
                created_at=timestamp,
                updated_at=timestamp,
                correlation_score=min(0.3 + frequency * 0.05, 0.9),
                correlation_type='entity',
                entities={entity_value},
                description=f"High activity ({len(recent_times)} events) from {entity_type} {entity_value}",
            )
        
        return None
    
    async def _correlate_anomaly(self, anomaly: AnomalyResult) -> None:
        """Correlate anomaly with other events."""
        cutoff = anomaly.timestamp - self.correlation_window
        
        # Find other anomalies in window
        related_anomalies = [
            a for ts, a in self._anomalies
            if ts >= cutoff and a != anomaly and a.is_anomaly
        ]
        
        if related_anomalies:
            # Multiple anomalies = elevated concern
            self._correlation_counter += 1
            
            all_anomalies = [anomaly] + related_anomalies
            avg_score = sum(a.anomaly_score for a in all_anomalies) / len(all_anomalies)
            
            corr = CorrelatedEvent(
                correlation_id=f"CORR-{self._correlation_counter:06d}",
                events=[],
                anomalies=all_anomalies,
                created_at=anomaly.timestamp,
                updated_at=anomaly.timestamp,
                correlation_score=min(avg_score + 0.2, 1.0),
                correlation_type='pattern',
                description=f"Multiple anomalies ({len(all_anomalies)}) detected in correlation window",
            )
            
            self._correlations[corr.correlation_id] = corr
            
            self.broadcast(
                self.MSG_CORRELATION_FOUND,
                corr.to_dict(),
                priority=MessagePriority.HIGH,
            )
    
    async def _detect_attack_chains(self) -> List[CorrelatedEvent]:
        """Detect multi-stage attack patterns."""
        chains = []
        cutoff = datetime.now() - timedelta(hours=1)
        
        # Get recent anomalies
        recent_anomalies = [
            a for ts, a in self._anomalies
            if ts >= cutoff and a.is_anomaly
        ]
        
        if len(recent_anomalies) < 2:
            return chains
        
        # Check for attack chain patterns
        for chain_name, stages in self._attack_chains.items():
            matched_stages = []
            
            for stage in stages:
                stage_matched = False
                for anomaly in recent_anomalies:
                    if self._matches_stage(anomaly, stage):
                        matched_stages.append(anomaly)
                        stage_matched = True
                        break
                
                if not stage_matched:
                    break
            
            # If multiple stages matched, it's an attack chain
            if len(matched_stages) >= 2:
                self._correlation_counter += 1
                
                chains.append(CorrelatedEvent(
                    correlation_id=f"CHAIN-{self._correlation_counter:06d}",
                    events=[],
                    anomalies=matched_stages,
                    created_at=matched_stages[0].timestamp,
                    updated_at=matched_stages[-1].timestamp,
                    correlation_score=0.7 + len(matched_stages) * 0.1,
                    correlation_type='attack_chain',
                    description=f"Attack chain detected: {chain_name} ({len(matched_stages)} stages)",
                ))
        
        return chains
    
    def _extract_entities(self, feature_set: FeatureSet) -> List[Tuple[str, str]]:
        """Extract entity identifiers from feature set."""
        entities = []
        metadata = feature_set.metadata
        raw_data = feature_set.raw_data
        
        if feature_set.source_type == 'network':
            if metadata.get('remote'):
                entities.append(('ip', metadata['remote'].split(':')[0]))
        
        elif feature_set.source_type == 'process':
            if metadata.get('user'):
                entities.append(('user', metadata['user']))
            if metadata.get('name'):
                entities.append(('process', metadata['name']))
        
        elif feature_set.source_type == 'log':
            # Extract IPs from log message
            if raw_data:
                import re
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(raw_data))
                for ip in ips[:3]:  # Limit to 3
                    entities.append(('ip', ip))
        
        return entities
    
    def _matches_stage(self, anomaly: AnomalyResult, stage: Dict[str, Any]) -> bool:
        """Check if anomaly matches attack chain stage."""
        if 'source_type' in stage:
            if anomaly.source_type != stage['source_type']:
                return False
        
        if 'min_score' in stage:
            if anomaly.anomaly_score < stage['min_score']:
                return False
        
        if 'reasons_contain' in stage:
            reasons_text = ' '.join(anomaly.reasons).lower()
            if stage['reasons_contain'].lower() not in reasons_text:
                return False
        
        return True
    
    async def _cleanup_old_events(self) -> None:
        """Remove events outside correlation window."""
        cutoff = datetime.now() - self.correlation_window * 2
        
        self._events = [(ts, fs) for ts, fs in self._events if ts >= cutoff]
        self._anomalies = [(ts, a) for ts, a in self._anomalies if ts >= cutoff]
        
        # Clean entity tracking
        for entity_events in [self._ip_events, self._user_events, self._process_events]:
            for entity in list(entity_events.keys()):
                entity_events[entity] = [t for t in entity_events[entity] if t >= cutoff]
                if not entity_events[entity]:
                    del entity_events[entity]
    
    def _define_attack_chains(self) -> Dict[str, List[Dict[str, Any]]]:
        """Define known attack chain patterns."""
        return {
            'reconnaissance_to_exploitation': [
                {'source_type': 'network', 'reasons_contain': 'scan'},
                {'source_type': 'log', 'reasons_contain': 'auth'},
                {'source_type': 'process', 'min_score': 0.6},
            ],
            'credential_stuffing': [
                {'source_type': 'log', 'reasons_contain': 'failure'},
                {'source_type': 'log', 'reasons_contain': 'failure'},
                {'source_type': 'log', 'reasons_contain': 'success'},
            ],
            'lateral_movement': [
                {'source_type': 'process', 'reasons_contain': 'suspicious'},
                {'source_type': 'network', 'reasons_contain': 'internal'},
                {'source_type': 'log', 'reasons_contain': 'login'},
            ],
            'data_exfiltration': [
                {'source_type': 'process', 'min_score': 0.5},
                {'source_type': 'network', 'reasons_contain': 'transfer'},
            ],
        }
    
    def get_active_correlations(self) -> List[Dict[str, Any]]:
        """Get all active correlations."""
        return [c.to_dict() for c in self._correlations.values()]
