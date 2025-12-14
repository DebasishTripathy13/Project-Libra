"""
ProjectLibra - Log Analyzer Service
Real-time log file analysis and pattern detection
"""

import re
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Pattern
from collections import Counter, deque
import logging

logger = logging.getLogger(__name__)


@dataclass
class LogPattern:
    """Known log pattern"""
    name: str
    regex: Pattern
    severity: str
    description: str


@dataclass
class LogEntry:
    """Parsed log entry"""
    timestamp: datetime
    level: str
    source: str
    message: str
    raw_line: str
    matched_patterns: List[str]


@dataclass
class LogAnalysisReport:
    """Log analysis summary"""
    total_lines: int
    parsed_lines: int
    by_level: Dict[str, int]
    by_source: Dict[str, int]
    matched_patterns: Dict[str, int]
    errors: List[str]
    warnings: List[str]
    criticals: List[str]
    recent_entries: List[LogEntry]


class LogAnalyzer:
    """
    Real-time log file analyzer.
    
    Parses log files, detects patterns, and identifies security issues.
    """
    
    # Common log patterns
    PATTERNS = [
        LogPattern(
            name='SSH_FAILED_LOGIN',
            regex=re.compile(r'Failed password for .+ from ([\d\.]+)', re.I),
            severity='warning',
            description='Failed SSH login attempt'
        ),
        LogPattern(
            name='SSH_SUCCESSFUL_LOGIN',
            regex=re.compile(r'Accepted password for (.+) from ([\d\.]+)', re.I),
            severity='info',
            description='Successful SSH login'
        ),
        LogPattern(
            name='SUDO_COMMAND',
            regex=re.compile(r'sudo:?\s+(\w+)\s+:.*COMMAND=(.+)', re.I),
            severity='info',
            description='Sudo command execution'
        ),
        LogPattern(
            name='SEGFAULT',
            regex=re.compile(r'segfault at', re.I),
            severity='error',
            description='Application segmentation fault'
        ),
        LogPattern(
            name='OUT_OF_MEMORY',
            regex=re.compile(r'Out of memory|OOM|killed process', re.I),
            severity='critical',
            description='Out of memory condition'
        ),
        LogPattern(
            name='KERNEL_PANIC',
            regex=re.compile(r'kernel panic|fatal exception', re.I),
            severity='critical',
            description='Kernel panic'
        ),
        LogPattern(
            name='SERVICE_START',
            regex=re.compile(r'Started|Starting (.+)', re.I),
            severity='info',
            description='Service started'
        ),
        LogPattern(
            name='SERVICE_STOP',
            regex=re.compile(r'Stopped|Stopping (.+)', re.I),
            severity='info',
            description='Service stopped'
        ),
        LogPattern(
            name='DISK_ERROR',
            regex=re.compile(r'I/O error|disk error|read error', re.I),
            severity='error',
            description='Disk I/O error'
        ),
        LogPattern(
            name='NETWORK_ERROR',
            regex=re.compile(r'Connection refused|Connection timed out|Network unreachable', re.I),
            severity='error',
            description='Network connectivity error'
        ),
        LogPattern(
            name='AUTHENTICATION_FAILURE',
            regex=re.compile(r'authentication failure|auth failed|invalid user', re.I),
            severity='warning',
            description='Authentication failure'
        ),
        LogPattern(
            name='PRIVILEGE_ESCALATION',
            regex=re.compile(r'gained privileges|escalated to root|became root', re.I),
            severity='warning',
            description='Privilege escalation'
        ),
        LogPattern(
            name='MALWARE_SIGNATURE',
            regex=re.compile(r'malware|virus|trojan|backdoor|rootkit', re.I),
            severity='critical',
            description='Malware signature detected'
        ),
        LogPattern(
            name='BRUTE_FORCE',
            regex=re.compile(r'multiple failed|repeated attempts|brute.?force', re.I),
            severity='warning',
            description='Possible brute force attack'
        ),
    ]
    
    # Log format parsers (syslog, apache, nginx, etc.)
    SYSLOG_REGEX = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.+)'
    )
    
    APACHE_REGEX = re.compile(
        r'(?P<ip>[\d\.]+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d\.]+"\s+'
        r'(?P<status>\d+)\s+(?P<size>\d+|-)'
    )
    
    SYSTEMD_REGEX = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<service>\S+)\[(?P<pid>\d+)\]:\s+'
        r'(?P<message>.+)'
    )
    
    def __init__(self, max_entries: int = 10000):
        self.max_entries = max_entries
        self._entries = deque(maxlen=max_entries)
        self._pattern_matches = Counter()
        self._level_counts = Counter()
        self._source_counts = Counter()
    
    def analyze_file(self, filepath: str, tail_lines: Optional[int] = None) -> LogAnalysisReport:
        """
        Analyze a log file.
        
        Args:
            filepath: Path to log file
            tail_lines: Only analyze last N lines (None = all)
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        total_lines = 0
        parsed_lines = 0
        errors = []
        warnings = []
        criticals = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
                if tail_lines:
                    lines = lines[-tail_lines:]
                
                for line in lines:
                    total_lines += 1
                    line = line.strip()
                    
                    if not line:
                        continue
                    
                    entry = self._parse_log_line(line)
                    if entry:
                        parsed_lines += 1
                        self._entries.append(entry)
                        self._level_counts[entry.level] += 1
                        self._source_counts[entry.source] += 1
                        
                        for pattern_name in entry.matched_patterns:
                            self._pattern_matches[pattern_name] += 1
                        
                        # Collect by severity
                        if entry.level == 'error':
                            errors.append(f"{entry.timestamp}: {entry.message[:100]}")
                        elif entry.level == 'warning':
                            warnings.append(f"{entry.timestamp}: {entry.message[:100]}")
                        elif entry.level == 'critical':
                            criticals.append(f"{entry.timestamp}: {entry.message[:100]}")
        
        except Exception as e:
            logger.error(f"Error analyzing log file: {e}")
            raise
        
        return LogAnalysisReport(
            total_lines=total_lines,
            parsed_lines=parsed_lines,
            by_level=dict(self._level_counts),
            by_source=dict(self._source_counts),
            matched_patterns=dict(self._pattern_matches),
            errors=errors[-50:],  # Last 50
            warnings=warnings[-50:],
            criticals=criticals[-50:],
            recent_entries=list(self._entries)[-100:],  # Last 100
        )
    
    def analyze_text(self, text: str) -> LogAnalysisReport:
        """Analyze log text (for pasted logs or stdin)"""
        lines = text.strip().split('\n')
        
        total_lines = 0
        parsed_lines = 0
        errors = []
        warnings = []
        criticals = []
        
        for line in lines:
            total_lines += 1
            line = line.strip()
            
            if not line:
                continue
            
            entry = self._parse_log_line(line)
            if entry:
                parsed_lines += 1
                self._entries.append(entry)
                self._level_counts[entry.level] += 1
                self._source_counts[entry.source] += 1
                
                for pattern_name in entry.matched_patterns:
                    self._pattern_matches[pattern_name] += 1
                
                if entry.level == 'error':
                    errors.append(f"{entry.timestamp}: {entry.message[:100]}")
                elif entry.level == 'warning':
                    warnings.append(f"{entry.timestamp}: {entry.message[:100]}")
                elif entry.level == 'critical':
                    criticals.append(f"{entry.timestamp}: {entry.message[:100]}")
        
        return LogAnalysisReport(
            total_lines=total_lines,
            parsed_lines=parsed_lines,
            by_level=dict(self._level_counts),
            by_source=dict(self._source_counts),
            matched_patterns=dict(self._pattern_matches),
            errors=errors[-50:],
            warnings=warnings[-50:],
            criticals=criticals[-50:],
            recent_entries=list(self._entries)[-100:],
        )
    
    def _parse_log_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line"""
        # Try syslog format
        match = self.SYSLOG_REGEX.match(line)
        if match:
            return self._parse_syslog(match, line)
        
        # Try systemd format
        match = self.SYSTEMD_REGEX.match(line)
        if match:
            return self._parse_systemd(match, line)
        
        # Try apache/nginx format
        match = self.APACHE_REGEX.match(line)
        if match:
            return self._parse_apache(match, line)
        
        # Generic fallback
        return self._parse_generic(line)
    
    def _parse_syslog(self, match: re.Match, raw_line: str) -> LogEntry:
        """Parse syslog format"""
        timestamp_str = match.group('timestamp')
        message = match.group('message')
        process = match.group('process')
        
        # Determine level from message
        level = self._detect_level(message)
        
        # Match patterns
        matched = self._match_patterns(message)
        
        return LogEntry(
            timestamp=self._parse_timestamp(timestamp_str),
            level=level,
            source=process,
            message=message,
            raw_line=raw_line,
            matched_patterns=matched,
        )
    
    def _parse_systemd(self, match: re.Match, raw_line: str) -> LogEntry:
        """Parse systemd format"""
        return self._parse_syslog(match, raw_line)
    
    def _parse_apache(self, match: re.Match, raw_line: str) -> LogEntry:
        """Parse Apache/nginx format"""
        status = int(match.group('status'))
        method = match.group('method')
        path = match.group('path')
        
        # HTTP status to log level
        if status >= 500:
            level = 'error'
        elif status >= 400:
            level = 'warning'
        else:
            level = 'info'
        
        message = f"{method} {path} -> {status}"
        matched = self._match_patterns(message)
        
        return LogEntry(
            timestamp=datetime.now(),  # Would parse from timestamp field
            level=level,
            source='httpd',
            message=message,
            raw_line=raw_line,
            matched_patterns=matched,
        )
    
    def _parse_generic(self, line: str) -> LogEntry:
        """Fallback generic parser"""
        level = self._detect_level(line)
        matched = self._match_patterns(line)
        
        return LogEntry(
            timestamp=datetime.now(),
            level=level,
            source='unknown',
            message=line,
            raw_line=line,
            matched_patterns=matched,
        )
    
    def _detect_level(self, message: str) -> str:
        """Detect log level from message"""
        message_lower = message.lower()
        
        if any(word in message_lower for word in ['panic', 'fatal', 'critical']):
            return 'critical'
        elif any(word in message_lower for word in ['error', 'fail', 'exception']):
            return 'error'
        elif any(word in message_lower for word in ['warn', 'warning']):
            return 'warning'
        elif any(word in message_lower for word in ['info', 'notice']):
            return 'info'
        else:
            return 'debug'
    
    def _match_patterns(self, message: str) -> List[str]:
        """Match message against known patterns"""
        matched = []
        
        for pattern in self.PATTERNS:
            if pattern.regex.search(message):
                matched.append(pattern.name)
        
        return matched
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string"""
        try:
            # Try common formats
            for fmt in ['%b %d %H:%M:%S', '%Y-%m-%d %H:%M:%S']:
                try:
                    dt = datetime.strptime(timestamp_str, fmt)
                    # Add current year if not present
                    if dt.year == 1900:
                        dt = dt.replace(year=datetime.now().year)
                    return dt
                except ValueError:
                    continue
        except Exception:
            pass
        
        return datetime.now()
    
    def get_statistics(self) -> Dict:
        """Get analysis statistics"""
        return {
            'total_entries': len(self._entries),
            'by_level': dict(self._level_counts),
            'by_source': dict(self._source_counts),
            'matched_patterns': dict(self._pattern_matches),
        }
