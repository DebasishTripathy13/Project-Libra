"""
AI Agents Package for ProjectLibra.

This package provides the agentic AI layer with specialized agents:
- ObservationAgent: Collects and preprocesses security data
- CorrelationAgent: Correlates events across sources
- ThreatReasoningAgent: Uses LLM for threat analysis
- MaintenanceAgent: Handles self-healing and remediation
- LearningAgent: Updates baselines and improves detection
"""

from .base_agent import BaseAgent, AgentMessage, AgentState
from .observation_agent import ObservationAgent
from .correlation_agent import CorrelationAgent
from .threat_agent import ThreatReasoningAgent
from .maintenance_agent import MaintenanceAgent
from .learning_agent import LearningAgent
from .orchestrator import AgentOrchestrator

# Aliases for convenience
ThreatAgent = ThreatReasoningAgent

__all__ = [
    'BaseAgent',
    'AgentMessage',
    'AgentState',
    'ObservationAgent',
    'CorrelationAgent',
    'ThreatReasoningAgent',
    'ThreatAgent',  # Alias
    'MaintenanceAgent',
    'LearningAgent',
    'AgentOrchestrator',
]
