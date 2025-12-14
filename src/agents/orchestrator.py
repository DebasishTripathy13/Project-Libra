"""
Agent Orchestrator for Coordinating All Agents.

Manages the lifecycle and communication of all security agents,
providing a unified interface for the platform.
"""

import asyncio
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set
from pathlib import Path
import logging

from .base_agent import BaseAgent, AgentMessage, AgentState, MessagePriority
from .observation_agent import ObservationAgent
from .correlation_agent import CorrelationAgent
from .threat_agent import ThreatReasoningAgent
from .maintenance_agent import MaintenanceAgent
from .learning_agent import LearningAgent
from ..database.dual_db_manager import DualDatabaseManager
from ..llm import BaseLLMClient, LLMConfig


class AgentOrchestrator:
    """
    Orchestrates all security agents.
    
    Responsibilities:
    - Agent lifecycle management
    - Message routing between agents
    - System-wide status monitoring
    - Configuration management
    - Graceful startup and shutdown
    """
    
    def __init__(
        self,
        data_dir: Optional[Path] = None,
        db_manager: Optional[DualDatabaseManager] = None,
        llm_client: Optional[BaseLLMClient] = None,
        llm_config: Optional[LLMConfig] = None,
        enable_auto_remediate: bool = False,
    ):
        """
        Initialize orchestrator.
        
        Args:
            data_dir: Base data directory
            db_manager: Database manager for tamper-proof storage
            llm_client: Pre-configured LLM client
            llm_config: LLM configuration
            enable_auto_remediate: Enable automatic remediation
        """
        self.data_dir = Path(data_dir) if data_dir else Path('./data')
        self.db_manager = db_manager
        self.llm_client = llm_client
        self.llm_config = llm_config
        self.enable_auto_remediate = enable_auto_remediate
        
        self.logger = logging.getLogger('orchestrator')
        
        # Agents
        self._agents: Dict[str, BaseAgent] = {}
        self._running = False
        self._started_at: Optional[datetime] = None
        
        # Message routing
        self._subscriptions: Dict[str, Set[str]] = {}  # message_type -> agent_ids
        
        # Statistics
        self._messages_routed = 0
    
    async def initialize(self) -> None:
        """Initialize all agents."""
        self.logger.info("Initializing agent orchestrator...")
        
        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Create agents
        self._create_agents()
        
        # Set up message routing
        self._setup_routing()
        
        self.logger.info(f"Initialized {len(self._agents)} agents")
    
    async def start(self) -> None:
        """Start all agents."""
        if self._running:
            return
        
        self.logger.info("Starting agent orchestrator...")
        
        # Start agents in order
        start_order = [
            'observation',  # First - data collection
            'learning',     # Second - baseline learning
            'correlation',  # Third - event correlation
            'threat',       # Fourth - threat analysis
            'maintenance',  # Last - remediation
        ]
        
        for agent_name in start_order:
            if agent_name in self._agents:
                try:
                    await self._agents[agent_name].start()
                    self.logger.info(f"Started {agent_name} agent")
                except Exception as e:
                    self.logger.error(f"Failed to start {agent_name} agent: {e}")
        
        self._running = True
        self._started_at = datetime.now()
        
        self.logger.info("Agent orchestrator started")
    
    async def stop(self) -> None:
        """Stop all agents."""
        if not self._running:
            return
        
        self.logger.info("Stopping agent orchestrator...")
        
        # Stop in reverse order
        stop_order = ['maintenance', 'threat', 'correlation', 'learning', 'observation']
        
        for agent_name in stop_order:
            if agent_name in self._agents:
                try:
                    await self._agents[agent_name].stop()
                    self.logger.info(f"Stopped {agent_name} agent")
                except Exception as e:
                    self.logger.error(f"Error stopping {agent_name} agent: {e}")
        
        self._running = False
        
        self.logger.info("Agent orchestrator stopped")
    
    async def run_forever(self) -> None:
        """Run the orchestrator until interrupted."""
        await self.initialize()
        await self.start()
        
        try:
            while self._running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()
    
    def _create_agents(self) -> None:
        """Create all agents."""
        # Observation Agent
        self._agents['observation'] = ObservationAgent(
            db_manager=self.db_manager,
            collection_interval=10.0,
            message_handler=self._route_message,
        )
        
        # Correlation Agent
        self._agents['correlation'] = CorrelationAgent(
            message_handler=self._route_message,
        )
        
        # Threat Reasoning Agent
        self._agents['threat'] = ThreatReasoningAgent(
            llm_client=self.llm_client,
            llm_config=self.llm_config,
            message_handler=self._route_message,
        )
        
        # Maintenance Agent
        self._agents['maintenance'] = MaintenanceAgent(
            auto_remediate=self.enable_auto_remediate,
            dry_run=not self.enable_auto_remediate,
            message_handler=self._route_message,
        )
        
        # Learning Agent
        self._agents['learning'] = LearningAgent(
            data_dir=self.data_dir / 'learning',
            message_handler=self._route_message,
        )
    
    def _setup_routing(self) -> None:
        """Set up message routing based on agent subscriptions."""
        # Default routing based on agent types
        self._subscriptions = {
            # Observation events go to correlation and learning
            'observation.feature_set': {'correlation', 'learning'},
            'observation.batch_complete': {'correlation'},
            
            # Correlation events go to threat and learning
            'correlation.found': {'threat'},
            'correlation.attack_chain': {'threat', 'maintenance'},
            
            # Threat events go to maintenance and learning
            'threat.assessment': {'maintenance', 'learning'},
            
            # Maintenance events go to learning for tracking
            'maintenance.action_executed': {'learning'},
            'maintenance.action_failed': {'learning'},
            
            # Learning feedback can be sent from anywhere
            'learning.feedback': {'learning'},
            
            # Anomaly events (from external detector)
            'anomaly.detected': {'correlation', 'threat', 'learning'},
            
            # Pattern events (from external detector)
            'pattern.matched': {'threat', 'correlation'},
        }
    
    def _route_message(self, message: AgentMessage) -> None:
        """Route message to appropriate agents."""
        self._messages_routed += 1
        
        # Get target agents
        targets = set()
        
        if message.recipient:
            # Direct message
            targets.add(message.recipient)
        else:
            # Broadcast - check subscriptions
            targets = self._subscriptions.get(message.message_type, set())
            
            # Also check wildcard subscriptions
            for agent_name, agent in self._agents.items():
                if agent.is_subscribed(message.message_type) or agent.is_subscribed('*'):
                    targets.add(agent_name)
        
        # Deliver to targets
        for target in targets:
            if target in self._agents:
                asyncio.create_task(
                    self._agents[target].receive_message(message)
                )
    
    def get_agent(self, name: str) -> Optional[BaseAgent]:
        """Get agent by name."""
        return self._agents.get(name)
    
    def get_status(self) -> Dict[str, Any]:
        """Get system status."""
        agent_statuses = {}
        for name, agent in self._agents.items():
            agent_statuses[name] = agent.get_status()
        
        return {
            'running': self._running,
            'started_at': self._started_at.isoformat() if self._started_at else None,
            'uptime_seconds': (datetime.now() - self._started_at).total_seconds() if self._started_at else 0,
            'messages_routed': self._messages_routed,
            'agent_count': len(self._agents),
            'agents': agent_statuses,
        }
    
    def get_health(self) -> Dict[str, Any]:
        """Get system health status."""
        healthy_agents = sum(
            1 for agent in self._agents.values()
            if agent.state in (AgentState.RUNNING, AgentState.IDLE)
        )
        
        error_agents = [
            name for name, agent in self._agents.items()
            if agent.state == AgentState.ERROR
        ]
        
        return {
            'healthy': len(error_agents) == 0 and self._running,
            'total_agents': len(self._agents),
            'healthy_agents': healthy_agents,
            'error_agents': error_agents,
            'status': 'healthy' if not error_agents else 'degraded' if healthy_agents > 0 else 'critical',
        }
    
    async def send_command(self, command: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Send a command to the system.
        
        Args:
            command: Command name
            params: Command parameters
            
        Returns:
            Command result
        """
        params = params or {}
        
        if command == 'pause':
            for agent in self._agents.values():
                await agent.pause()
            return {'status': 'paused'}
        
        elif command == 'resume':
            for agent in self._agents.values():
                await agent.resume()
            return {'status': 'resumed'}
        
        elif command == 'collect_now':
            # Trigger immediate collection
            observation = self._agents.get('observation')
            if observation:
                message = AgentMessage(
                    sender='orchestrator',
                    recipient='observation',
                    message_type='control.collect_now',
                    payload=params,
                )
                await observation.receive_message(message)
                return {'status': 'collection_triggered'}
        
        elif command == 'feedback':
            # Submit learning feedback
            learning = self._agents.get('learning')
            if learning:
                message = AgentMessage(
                    sender='orchestrator',
                    recipient='learning',
                    message_type='learning.feedback',
                    payload=params,
                )
                await learning.receive_message(message)
                return {'status': 'feedback_submitted'}
        
        elif command == 'analyze':
            # Request threat analysis
            threat = self._agents.get('threat')
            if threat:
                message = AgentMessage(
                    sender='orchestrator',
                    recipient='threat',
                    message_type='request.analyze',
                    payload=params,
                )
                await threat.receive_message(message)
                return {'status': 'analysis_requested'}
        
        elif command == 'approve_action':
            # Approve maintenance action
            maintenance = self._agents.get('maintenance')
            if maintenance:
                message = AgentMessage(
                    sender='orchestrator',
                    recipient='maintenance',
                    message_type='maintenance.approve',
                    payload=params,
                )
                await maintenance.receive_message(message)
                return {'status': 'action_approved'}
        
        return {'status': 'unknown_command', 'command': command}
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get aggregated metrics from all agents."""
        metrics = {
            'orchestrator': {
                'messages_routed': self._messages_routed,
            }
        }
        
        # Learning metrics
        learning = self._agents.get('learning')
        if learning and hasattr(learning, 'get_learning_metrics'):
            metrics['learning'] = learning.get_learning_metrics()
        
        # Observation stats
        observation = self._agents.get('observation')
        if observation and hasattr(observation, 'get_collection_stats'):
            metrics['collection'] = observation.get_collection_stats()
        
        # Correlation stats
        correlation = self._agents.get('correlation')
        if correlation and hasattr(correlation, 'get_active_correlations'):
            correlations = correlation.get_active_correlations()
            metrics['correlations'] = {
                'active_count': len(correlations),
            }
        
        # Threat assessments
        threat = self._agents.get('threat')
        if threat and hasattr(threat, 'get_recent_assessments'):
            assessments = threat.get_recent_assessments(limit=5)
            metrics['recent_threats'] = assessments
        
        # Maintenance actions
        maintenance = self._agents.get('maintenance')
        if maintenance:
            if hasattr(maintenance, 'get_pending_actions'):
                metrics['pending_actions'] = len(maintenance.get_pending_actions())
            if hasattr(maintenance, 'get_recent_actions'):
                metrics['recent_actions'] = maintenance.get_recent_actions(limit=5)
        
        return metrics
