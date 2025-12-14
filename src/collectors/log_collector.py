"""
ProjectLibra - Log Collector
Cross-platform system log collection
"""

import os
import re
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path

from .base_collector import BaseCollector, CollectedEvent, EventSeverity

logger = logging.getLogger(__name__)


class LogCollector(BaseCollector):
    """
    Collects system logs from various sources.
    Supports Linux, Windows, and macOS.
    """
    
    # Log patterns for parsing
    SYSLOG_PATTERN = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.*)$'
    )
    
    AUTH_PATTERNS = {
        'login_success': re.compile(r'Accepted\s+(password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)'),
        'login_failure': re.compile(r'Failed\s+(password|publickey)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)'),
        'sudo': re.compile(r'(\S+)\s+:\s+.*COMMAND=(.*)'),
        'session_open': re.compile(r'session opened for user (\S+)'),
        'session_close': re.compile(r'session closed for user (\S+)'),
    }
    
    # Severity keywords
    SEVERITY_KEYWORDS = {
        'critical': ['critical', 'fatal', 'emergency', 'panic'],
        'error': ['error', 'fail', 'failed', 'denied', 'refused'],
        'warning': ['warning', 'warn', 'timeout', 'retry'],
        'info': ['info', 'notice', 'accepted', 'started', 'opened'],
        'debug': ['debug', 'trace']
    }
    
    def __init__(self, 
                 host_id: Optional[str] = None,
                 log_paths: Optional[List[str]] = None,
                 lookback_minutes: int = 5):
        """
        Initialize the log collector.
        
        Args:
            host_id: Host identifier
            log_paths: Custom log file paths to monitor
            lookback_minutes: How far back to look for logs
        """
        super().__init__(host_id)
        self.log_paths = log_paths or self._get_default_log_paths()
        self.lookback_minutes = lookback_minutes
        self._last_positions: Dict[str, int] = {}
    
    def _get_default_log_paths(self) -> List[str]:
        """Get default log paths based on OS"""
        if self.os_type == 'linux':
            return [
                '/var/log/syslog',
                '/var/log/auth.log',
                '/var/log/messages',
                '/var/log/secure',
                '/var/log/kern.log'
            ]
        elif self.os_type == 'macos':
            return [
                '/var/log/system.log',
                '/var/log/secure.log'
            ]
        elif self.os_type == 'windows':
            # Windows uses Event Log API, handled separately
            return []
        return []
    
    def get_source_name(self) -> str:
        return "log_collector"
    
    def collect(self) -> List[CollectedEvent]:
        """Collect log events from all configured sources"""
        events = []
        
        if self.os_type == 'windows':
            events.extend(self._collect_windows_events())
        else:
            for log_path in self.log_paths:
                if os.path.exists(log_path):
                    try:
                        events.extend(self._collect_from_file(log_path))
                    except PermissionError:
                        logger.warning(f"Permission denied: {log_path}")
                    except Exception as e:
                        logger.error(f"Error reading {log_path}: {e}")
        
        return events
    
    def _collect_from_file(self, log_path: str) -> List[CollectedEvent]:
        """Collect events from a single log file"""
        events = []
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Get file position
                last_pos = self._last_positions.get(log_path, 0)
                
                # Seek to last position or start from end if first run
                if last_pos == 0:
                    # First run: only get recent entries
                    f.seek(0, 2)  # End of file
                    file_size = f.tell()
                    # Read last 100KB or so
                    start_pos = max(0, file_size - 102400)
                    f.seek(start_pos)
                    if start_pos > 0:
                        f.readline()  # Skip partial line
                else:
                    f.seek(last_pos)
                
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    event = self._parse_log_line(line, log_path)
                    if event:
                        events.append(event)
                
                # Save position
                self._last_positions[log_path] = f.tell()
                
        except Exception as e:
            logger.error(f"Error collecting from {log_path}: {e}")
        
        return events
    
    def _parse_log_line(self, line: str, source_file: str) -> Optional[CollectedEvent]:
        """Parse a single log line into an event"""
        
        # Try syslog format
        match = self.SYSLOG_PATTERN.match(line)
        
        if match:
            raw_data = {
                'timestamp_str': match.group('timestamp'),
                'hostname': match.group('hostname'),
                'process': match.group('process'),
                'pid': match.group('pid'),
                'message': match.group('message'),
                'source_file': source_file,
                'raw_line': line
            }
            
            # Determine event type and extract additional info
            event_type, normalized = self._analyze_log_message(
                match.group('message'),
                match.group('process')
            )
            
            # Determine severity
            severity = self._determine_severity(match.group('message'))
            
            return self._create_event(
                event_type=event_type,
                severity=severity,
                raw_data=raw_data,
                normalized_data=normalized,
                tags=self._extract_tags(match.group('message'), source_file),
                metadata={'source_file': source_file}
            )
        else:
            # Generic log entry
            severity = self._determine_severity(line)
            return self._create_event(
                event_type='generic_log',
                severity=severity,
                raw_data={'raw_line': line, 'source_file': source_file},
                normalized_data={'message': line},
                tags=['unparsed'],
                metadata={'source_file': source_file}
            )
    
    def _analyze_log_message(self, message: str, process: str) -> tuple:
        """Analyze log message to determine type and extract details"""
        normalized = {'message': message, 'process': process}
        event_type = 'log_entry'
        
        # Check auth patterns
        for pattern_name, pattern in self.AUTH_PATTERNS.items():
            match = pattern.search(message)
            if match:
                event_type = pattern_name
                groups = match.groups()
                
                if pattern_name == 'login_success':
                    normalized.update({
                        'auth_method': groups[0],
                        'username': groups[1],
                        'source_ip': groups[2],
                        'action': 'login',
                        'outcome': 'success'
                    })
                elif pattern_name == 'login_failure':
                    normalized.update({
                        'auth_method': groups[0],
                        'username': groups[1],
                        'source_ip': groups[2],
                        'action': 'login',
                        'outcome': 'failure'
                    })
                elif pattern_name == 'sudo':
                    normalized.update({
                        'username': groups[0],
                        'command': groups[1],
                        'action': 'privilege_escalation'
                    })
                elif pattern_name in ['session_open', 'session_close']:
                    normalized.update({
                        'username': groups[0],
                        'action': 'session',
                        'outcome': 'open' if 'open' in pattern_name else 'close'
                    })
                break
        
        return event_type, normalized
    
    def _determine_severity(self, message: str) -> str:
        """Determine severity from message content"""
        message_lower = message.lower()
        
        for severity, keywords in self.SEVERITY_KEYWORDS.items():
            if any(kw in message_lower for kw in keywords):
                return severity
        
        return 'info'
    
    def _extract_tags(self, message: str, source_file: str) -> List[str]:
        """Extract tags from message and source"""
        tags = []
        
        # Add source-based tags
        if 'auth' in source_file.lower():
            tags.append('authentication')
        if 'secure' in source_file.lower():
            tags.append('security')
        if 'kern' in source_file.lower():
            tags.append('kernel')
        
        # Add content-based tags
        message_lower = message.lower()
        if 'ssh' in message_lower:
            tags.append('ssh')
        if 'sudo' in message_lower:
            tags.append('sudo')
        if 'fail' in message_lower or 'denied' in message_lower:
            tags.append('security_event')
        
        return tags
    
    def _collect_windows_events(self) -> List[CollectedEvent]:
        """Collect Windows Event Log entries"""
        events = []
        
        try:
            import win32evtlog
            import win32evtlogutil
            
            log_types = ['Security', 'System', 'Application']
            
            for log_type in log_types:
                try:
                    hand = win32evtlog.OpenEventLog(None, log_type)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    
                    total = win32evtlog.GetNumberOfEventLogRecords(hand)
                    events_read = 0
                    max_events = 100  # Limit per collection
                    
                    while events_read < max_events:
                        records = win32evtlog.ReadEventLog(hand, flags, 0)
                        if not records:
                            break
                        
                        for record in records:
                            if events_read >= max_events:
                                break
                            
                            event = self._parse_windows_event(record, log_type)
                            if event:
                                events.append(event)
                            events_read += 1
                    
                    win32evtlog.CloseEventLog(hand)
                except Exception as e:
                    logger.warning(f"Error reading {log_type} log: {e}")
                    
        except ImportError:
            logger.warning("win32evtlog not available - Windows event collection disabled")
        
        return events
    
    def _parse_windows_event(self, record, log_type: str) -> Optional[CollectedEvent]:
        """Parse a Windows event record"""
        try:
            severity_map = {
                1: 'error',      # EVENTLOG_ERROR_TYPE
                2: 'warning',    # EVENTLOG_WARNING_TYPE
                4: 'info',       # EVENTLOG_INFORMATION_TYPE
                8: 'info',       # EVENTLOG_AUDIT_SUCCESS
                16: 'warning'    # EVENTLOG_AUDIT_FAILURE
            }
            
            raw_data = {
                'event_id': record.EventID,
                'source_name': record.SourceName,
                'event_type': record.EventType,
                'time_generated': str(record.TimeGenerated),
                'log_type': log_type,
                'data': str(record.StringInserts) if record.StringInserts else ''
            }
            
            normalized = {
                'event_id': record.EventID & 0xFFFF,  # Mask to get actual event ID
                'source': record.SourceName,
                'message': str(record.StringInserts) if record.StringInserts else '',
                'log_type': log_type
            }
            
            return self._create_event(
                event_type=f"windows_{log_type.lower()}_event",
                severity=severity_map.get(record.EventType, 'info'),
                raw_data=raw_data,
                normalized_data=normalized,
                tags=['windows', log_type.lower()]
            )
        except Exception as e:
            logger.error(f"Error parsing Windows event: {e}")
            return None
