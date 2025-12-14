"""
ProjectLibra - Base Collector
Abstract base class for all data collectors
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional
from enum import Enum
import hashlib
import json
import uuid
import platform


class EventSeverity(Enum):
    """Severity levels for collected events"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventSource(Enum):
    """Sources of collected events"""
    SYSLOG = "syslog"
    AUTH_LOG = "auth_log"
    PROCESS = "process"
    NETWORK = "network"
    METRICS = "metrics"
    FILE_SYSTEM = "file_system"
    SECURITY = "security"
    APPLICATION = "application"


@dataclass
class CollectedEvent:
    """
    Standardized event structure for all collectors.
    This is the universal format that all collectors produce.
    """
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    host_id: str
    os_type: str
    raw_data: Dict[str, Any]
    normalized_data: Dict[str, Any]
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    _hash: Optional[str] = field(default=None, repr=False)
    
    def __post_init__(self):
        """Compute hash after initialization"""
        if self._hash is None:
            self._hash = self.compute_hash()
    
    @property
    def hash(self) -> str:
        """Get the event hash"""
        if self._hash is None:
            self._hash = self.compute_hash()
        return self._hash
    
    def compute_hash(self) -> str:
        """Compute cryptographic hash of event content"""
        content = json.dumps({
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'event_type': self.event_type,
            'raw_data': self.raw_data
        }, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'event_type': self.event_type,
            'severity': self.severity,
            'host_id': self.host_id,
            'os_type': self.os_type,
            'raw_data': self.raw_data,
            'normalized_data': self.normalized_data,
            'tags': self.tags,
            'metadata': self.metadata,
            'hash': self.hash
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CollectedEvent':
        """Create from dictionary"""
        return cls(
            event_id=data['event_id'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            source=data['source'],
            event_type=data['event_type'],
            severity=data['severity'],
            host_id=data['host_id'],
            os_type=data['os_type'],
            raw_data=data['raw_data'],
            normalized_data=data['normalized_data'],
            tags=data.get('tags', []),
            metadata=data.get('metadata', {}),
            _hash=data.get('hash')
        )


class BaseCollector(ABC):
    """
    Abstract base class for all data collectors.
    
    Collectors are responsible for gathering data from various system sources
    and converting them into standardized CollectedEvent objects.
    """
    
    def __init__(self, host_id: Optional[str] = None):
        """
        Initialize the collector.
        
        Args:
            host_id: Unique identifier for this host. Auto-generated if not provided.
        """
        self.host_id = host_id or self._generate_host_id()
        self.os_type = self._detect_os()
        self._running = False
        self._event_count = 0
    
    def _generate_host_id(self) -> str:
        """Generate a unique host identifier"""
        import socket
        hostname = socket.gethostname()
        return f"{hostname}-{uuid.uuid4().hex[:8]}"
    
    def _detect_os(self) -> str:
        """Detect the operating system"""
        system = platform.system().lower()
        if system == 'darwin':
            return 'macos'
        return system  # 'linux' or 'windows'
    
    def _generate_event_id(self) -> str:
        """Generate a unique event ID"""
        return f"evt-{uuid.uuid4().hex[:12]}"
    
    def _create_event(self,
                      event_type: str,
                      severity: str,
                      raw_data: Dict[str, Any],
                      normalized_data: Dict[str, Any],
                      tags: Optional[List[str]] = None,
                      metadata: Optional[Dict[str, Any]] = None) -> CollectedEvent:
        """
        Create a standardized event.
        
        Args:
            event_type: Type of event (e.g., 'login_attempt', 'process_start')
            severity: Severity level
            raw_data: Original raw data from the source
            normalized_data: Normalized/processed data
            tags: Optional tags for categorization
            metadata: Optional additional metadata
            
        Returns:
            CollectedEvent instance
        """
        self._event_count += 1
        
        return CollectedEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.now(),
            source=self.get_source_name(),
            event_type=event_type,
            severity=severity,
            host_id=self.host_id,
            os_type=self.os_type,
            raw_data=raw_data,
            normalized_data=normalized_data,
            tags=tags or [],
            metadata=metadata or {}
        )
    
    @abstractmethod
    def collect(self) -> List[CollectedEvent]:
        """
        Collect events from the source.
        
        Returns:
            List of collected events
        """
        pass
    
    @abstractmethod
    def get_source_name(self) -> str:
        """
        Return the collector source identifier.
        
        Returns:
            Source name string
        """
        pass
    
    def start(self):
        """Start the collector"""
        self._running = True
    
    def stop(self):
        """Stop the collector"""
        self._running = False
    
    def is_running(self) -> bool:
        """Check if collector is running"""
        return self._running
    
    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics"""
        return {
            'source': self.get_source_name(),
            'host_id': self.host_id,
            'os_type': self.os_type,
            'running': self._running,
            'events_collected': self._event_count
        }
