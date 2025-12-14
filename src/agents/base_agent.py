"""
Base Agent Module for Agentic AI System.

Provides the foundation for all specialized agents with
common interfaces, state management, and communication.
"""

import asyncio
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
import logging


class AgentState(Enum):
    """Agent operational states."""
    IDLE = 'idle'
    RUNNING = 'running'
    PAUSED = 'paused'
    ERROR = 'error'
    STOPPED = 'stopped'


class MessagePriority(Enum):
    """Message priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class AgentMessage:
    """
    Message for inter-agent communication.
    
    Agents communicate using typed messages that can
    carry any payload and track routing information.
    """
    
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sender: str = ''
    recipient: str = ''  # Empty for broadcast
    message_type: str = ''
    payload: Any = None
    timestamp: datetime = field(default_factory=datetime.now)
    priority: MessagePriority = MessagePriority.NORMAL
    correlation_id: Optional[str] = None  # For request-response patterns
    ttl: int = 300  # Time to live in seconds
    
    def is_expired(self) -> bool:
        """Check if message has expired."""
        age = (datetime.now() - self.timestamp).total_seconds()
        return age > self.ttl
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'message_id': self.message_id,
            'sender': self.sender,
            'recipient': self.recipient,
            'message_type': self.message_type,
            'payload': self.payload,
            'timestamp': self.timestamp.isoformat(),
            'priority': self.priority.value,
            'correlation_id': self.correlation_id,
            'ttl': self.ttl,
        }


@dataclass
class AgentMetrics:
    """Runtime metrics for an agent."""
    
    messages_received: int = 0
    messages_sent: int = 0
    messages_processed: int = 0
    errors_count: int = 0
    last_activity: Optional[datetime] = None
    processing_time_total: float = 0.0
    
    @property
    def avg_processing_time(self) -> float:
        """Average message processing time."""
        if self.messages_processed == 0:
            return 0.0
        return self.processing_time_total / self.messages_processed


class BaseAgent(ABC):
    """
    Abstract base class for all agents.
    
    Provides common functionality:
    - State management
    - Message handling
    - Lifecycle management
    - Metrics collection
    - Error handling
    """
    
    def __init__(
        self,
        agent_id: Optional[str] = None,
        name: str = 'BaseAgent',
        description: str = '',
        message_handler: Optional[Callable[[AgentMessage], None]] = None,
    ):
        """
        Initialize agent.
        
        Args:
            agent_id: Unique agent identifier
            name: Human-readable name
            description: Agent description
            message_handler: Callback for outbound messages
        """
        self.agent_id = agent_id or str(uuid.uuid4())
        self.name = name
        self.description = description
        
        self._state = AgentState.IDLE
        self._message_queue: asyncio.Queue = asyncio.Queue()
        self._message_handler = message_handler
        self._subscriptions: Set[str] = set()
        self._running = False
        self._task: Optional[asyncio.Task] = None
        
        self.metrics = AgentMetrics()
        self.logger = logging.getLogger(f'agent.{name}')
        
        # Configuration
        self.config: Dict[str, Any] = {}
    
    @property
    def state(self) -> AgentState:
        """Get current agent state."""
        return self._state
    
    @state.setter
    def state(self, new_state: AgentState) -> None:
        """Set agent state with logging."""
        old_state = self._state
        self._state = new_state
        self.logger.info(f"State changed: {old_state.value} -> {new_state.value}")
    
    async def start(self) -> None:
        """Start the agent."""
        if self._running:
            return
        
        self._running = True
        self.state = AgentState.RUNNING
        
        # Initialize agent
        await self._initialize()
        
        # Start message processing loop
        self._task = asyncio.create_task(self._process_loop())
        
        self.logger.info(f"Agent {self.name} started")
    
    async def stop(self) -> None:
        """Stop the agent."""
        self._running = False
        self.state = AgentState.STOPPED
        
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        await self._cleanup()
        self.logger.info(f"Agent {self.name} stopped")
    
    async def pause(self) -> None:
        """Pause agent processing."""
        if self._state == AgentState.RUNNING:
            self.state = AgentState.PAUSED
    
    async def resume(self) -> None:
        """Resume agent processing."""
        if self._state == AgentState.PAUSED:
            self.state = AgentState.RUNNING
    
    async def receive_message(self, message: AgentMessage) -> None:
        """
        Receive a message for processing.
        
        Args:
            message: Message to process
        """
        if message.is_expired():
            self.logger.debug(f"Dropped expired message: {message.message_id}")
            return
        
        self.metrics.messages_received += 1
        await self._message_queue.put(message)
    
    def send_message(
        self,
        recipient: str,
        message_type: str,
        payload: Any,
        priority: MessagePriority = MessagePriority.NORMAL,
        correlation_id: Optional[str] = None,
    ) -> AgentMessage:
        """
        Send a message to another agent.
        
        Args:
            recipient: Target agent ID (empty for broadcast)
            message_type: Type of message
            payload: Message payload
            priority: Message priority
            correlation_id: For request-response correlation
            
        Returns:
            The sent message
        """
        message = AgentMessage(
            sender=self.agent_id,
            recipient=recipient,
            message_type=message_type,
            payload=payload,
            priority=priority,
            correlation_id=correlation_id,
        )
        
        self.metrics.messages_sent += 1
        
        if self._message_handler:
            self._message_handler(message)
        
        return message
    
    def broadcast(
        self,
        message_type: str,
        payload: Any,
        priority: MessagePriority = MessagePriority.NORMAL,
    ) -> AgentMessage:
        """
        Broadcast message to all agents.
        
        Args:
            message_type: Type of message
            payload: Message payload
            priority: Message priority
            
        Returns:
            The broadcast message
        """
        return self.send_message('', message_type, payload, priority)
    
    def subscribe(self, message_type: str) -> None:
        """Subscribe to a message type."""
        self._subscriptions.add(message_type)
    
    def unsubscribe(self, message_type: str) -> None:
        """Unsubscribe from a message type."""
        self._subscriptions.discard(message_type)
    
    def is_subscribed(self, message_type: str) -> bool:
        """Check if subscribed to message type."""
        return message_type in self._subscriptions or '*' in self._subscriptions
    
    async def _process_loop(self) -> None:
        """Main message processing loop."""
        while self._running:
            try:
                # Wait for message with timeout
                try:
                    message = await asyncio.wait_for(
                        self._message_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    # No message, run periodic tasks
                    if self._state == AgentState.RUNNING:
                        await self._periodic_task()
                    continue
                
                if self._state != AgentState.RUNNING:
                    # Re-queue if paused
                    if self._state == AgentState.PAUSED:
                        await self._message_queue.put(message)
                    await asyncio.sleep(0.1)
                    continue
                
                # Process message
                start_time = datetime.now()
                try:
                    await self._handle_message(message)
                    self.metrics.messages_processed += 1
                except Exception as e:
                    self.logger.error(f"Error processing message: {e}")
                    self.metrics.errors_count += 1
                    await self._handle_error(e, message)
                
                elapsed = (datetime.now() - start_time).total_seconds()
                self.metrics.processing_time_total += elapsed
                self.metrics.last_activity = datetime.now()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in process loop: {e}")
                self.state = AgentState.ERROR
                await asyncio.sleep(1)
    
    @abstractmethod
    async def _initialize(self) -> None:
        """
        Initialize agent resources.
        
        Override to set up agent-specific resources.
        """
        pass
    
    @abstractmethod
    async def _cleanup(self) -> None:
        """
        Clean up agent resources.
        
        Override to clean up agent-specific resources.
        """
        pass
    
    @abstractmethod
    async def _handle_message(self, message: AgentMessage) -> None:
        """
        Handle an incoming message.
        
        Args:
            message: Message to handle
        """
        pass
    
    async def _periodic_task(self) -> None:
        """
        Periodic task executed when no messages.
        
        Override to add periodic behavior.
        """
        pass
    
    async def _handle_error(self, error: Exception, message: AgentMessage) -> None:
        """
        Handle processing error.
        
        Args:
            error: The exception that occurred
            message: Message being processed when error occurred
        """
        self.logger.error(f"Error handling message {message.message_id}: {error}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status information."""
        return {
            'agent_id': self.agent_id,
            'name': self.name,
            'state': self._state.value,
            'queue_size': self._message_queue.qsize(),
            'metrics': {
                'messages_received': self.metrics.messages_received,
                'messages_sent': self.metrics.messages_sent,
                'messages_processed': self.metrics.messages_processed,
                'errors_count': self.metrics.errors_count,
                'avg_processing_time': self.metrics.avg_processing_time,
                'last_activity': self.metrics.last_activity.isoformat() if self.metrics.last_activity else None,
            },
            'subscriptions': list(self._subscriptions),
        }
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id={self.agent_id}, name={self.name}, state={self._state.value})"
