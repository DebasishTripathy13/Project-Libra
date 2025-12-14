"""
Feature Extraction Module for ML Pipeline.

Extracts numerical features from raw security events
for use in anomaly detection and baseline learning.
"""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from collections import Counter
import math


@dataclass
class FeatureSet:
    """Container for extracted features."""
    
    timestamp: datetime
    source_type: str  # 'log', 'process', 'network', 'metric'
    features: Dict[str, float]
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_data: Optional[Any] = None
    
    def to_vector(self, feature_names: List[str]) -> List[float]:
        """Convert to ordered feature vector."""
        return [self.features.get(name, 0.0) for name in feature_names]
    
    def __repr__(self) -> str:
        return f"FeatureSet({self.source_type}, {len(self.features)} features)"


class FeatureExtractor:
    """
    Extracts numerical features from security events.
    
    Converts raw logs, process data, network events, and metrics
    into numerical feature vectors for ML analysis.
    """
    
    # Log severity mappings
    SEVERITY_SCORES = {
        'debug': 0.1,
        'info': 0.2,
        'notice': 0.3,
        'warning': 0.5,
        'warn': 0.5,
        'error': 0.7,
        'err': 0.7,
        'critical': 0.9,
        'crit': 0.9,
        'alert': 0.95,
        'emergency': 1.0,
        'emerg': 1.0,
    }
    
    # Suspicious patterns in logs
    SUSPICIOUS_PATTERNS = [
        (r'failed\s+password', 'auth_failure', 0.7),
        (r'authentication\s+failure', 'auth_failure', 0.7),
        (r'invalid\s+user', 'invalid_user', 0.6),
        (r'connection\s+refused', 'conn_refused', 0.4),
        (r'permission\s+denied', 'perm_denied', 0.5),
        (r'segfault|segmentation\s+fault', 'crash', 0.8),
        (r'out\s+of\s+memory|oom', 'resource_exhaustion', 0.9),
        (r'root\s+login', 'root_access', 0.6),
        (r'sudo|su\s+:', 'privilege_escalation', 0.5),
        (r'cron|scheduled', 'scheduled_task', 0.2),
        (r'ssh|sshd', 'ssh_activity', 0.3),
        (r'firewall|iptables|nftables', 'firewall_event', 0.4),
        (r'malware|virus|trojan', 'malware_indicator', 1.0),
        (r'brute\s*force|bruteforce', 'brute_force', 0.9),
        (r'scan|nmap|masscan', 'scanning', 0.7),
    ]
    
    # Suspicious process characteristics
    SUSPICIOUS_PROCESS_NAMES = [
        'nc', 'netcat', 'ncat',
        'nmap', 'masscan', 'zmap',
        'hydra', 'medusa', 'john',
        'hashcat', 'mimikatz',
        'msfconsole', 'meterpreter',
        'powershell', 'cmd.exe',
        'wget', 'curl', 'fetch',  # Not inherently suspicious, but trackable
    ]
    
    # Known safe ports
    SAFE_PORTS = {22, 80, 443, 53, 25, 587, 993, 995, 3306, 5432, 27017}
    
    def __init__(self):
        """Initialize feature extractor."""
        self._compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), name, score)
            for pattern, name, score in self.SUSPICIOUS_PATTERNS
        ]
        
    def extract_log_features(
        self,
        message: str,
        source: str = 'unknown',
        timestamp: Optional[datetime] = None,
        severity: Optional[str] = None,
    ) -> FeatureSet:
        """
        Extract features from a log message.
        
        Args:
            message: Log message text
            source: Log source (syslog, auth, etc.)
            timestamp: Event timestamp (datetime object or ISO string)
            severity: Log severity level
            
        Returns:
            FeatureSet with extracted features
        """
        # Handle timestamp - convert string to datetime if needed
        if timestamp is None:
            timestamp = datetime.now()
        elif isinstance(timestamp, str):
            try:
                # Try ISO format first
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                try:
                    # Try common formats
                    from dateutil import parser
                    timestamp = parser.parse(timestamp)
                except:
                    # Fallback to now if parsing fails
                    timestamp = datetime.now()
        
        features = {}
        metadata = {'source': source, 'original_message': message[:200]}
        
        # Basic text features
        features['message_length'] = len(message)
        features['word_count'] = len(message.split())
        features['uppercase_ratio'] = sum(1 for c in message if c.isupper()) / max(len(message), 1)
        features['digit_ratio'] = sum(1 for c in message if c.isdigit()) / max(len(message), 1)
        features['special_char_ratio'] = sum(1 for c in message if not c.isalnum() and c != ' ') / max(len(message), 1)
        
        # Severity score
        if severity:
            features['severity_score'] = self.SEVERITY_SCORES.get(severity.lower(), 0.3)
        else:
            # Try to detect severity from message
            features['severity_score'] = self._detect_severity(message)
        
        # Time-based features
        features['hour_of_day'] = timestamp.hour / 24.0
        features['day_of_week'] = timestamp.weekday() / 7.0
        features['is_business_hours'] = 1.0 if 9 <= timestamp.hour <= 17 and timestamp.weekday() < 5 else 0.0
        features['is_weekend'] = 1.0 if timestamp.weekday() >= 5 else 0.0
        
        # Pattern matching
        pattern_scores = []
        detected_patterns = []
        
        for pattern, name, score in self._compiled_patterns:
            if pattern.search(message):
                pattern_scores.append(score)
                detected_patterns.append(name)
                features[f'pattern_{name}'] = 1.0
            else:
                features[f'pattern_{name}'] = 0.0
        
        features['max_pattern_score'] = max(pattern_scores) if pattern_scores else 0.0
        features['avg_pattern_score'] = sum(pattern_scores) / len(pattern_scores) if pattern_scores else 0.0
        features['pattern_count'] = len(pattern_scores)
        
        metadata['detected_patterns'] = detected_patterns
        
        # IP address detection
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, message)
        features['ip_count'] = len(ips)
        features['has_private_ip'] = 1.0 if any(self._is_private_ip(ip) for ip in ips) else 0.0
        
        # Port detection
        port_pattern = r'\bport[:\s]+(\d+)\b|\b:(\d{2,5})\b'
        ports = [int(m[0] or m[1]) for m in re.findall(port_pattern, message, re.IGNORECASE)]
        features['port_count'] = len(ports)
        features['has_unusual_port'] = 1.0 if any(p not in self.SAFE_PORTS for p in ports) else 0.0
        
        # Path detection
        path_pattern = r'[/\\][\w./\\-]+'
        paths = re.findall(path_pattern, message)
        features['path_count'] = len(paths)
        features['has_sensitive_path'] = 1.0 if any(self._is_sensitive_path(p) for p in paths) else 0.0
        
        # Source-specific features
        source_scores = {
            'auth': 0.6,
            'secure': 0.6,
            'syslog': 0.3,
            'kernel': 0.5,
            'cron': 0.2,
            'messages': 0.3,
        }
        features['source_sensitivity'] = source_scores.get(source.lower(), 0.3)
        
        # Entropy (indicates potential obfuscation or encoding)
        features['entropy'] = self._calculate_entropy(message)
        
        return FeatureSet(
            timestamp=timestamp,
            source_type='log',
            features=features,
            metadata=metadata,
            raw_data=message,
        )
    
    def extract_process_features(
        self,
        pid: int,
        name: str,
        cmdline: str,
        user: str,
        cpu_percent: float,
        memory_percent: float,
        connections: int = 0,
        open_files: int = 0,
        children: int = 0,
        timestamp: Optional[datetime] = None,
    ) -> FeatureSet:
        """
        Extract features from process data.
        
        Args:
            pid: Process ID
            name: Process name
            cmdline: Full command line
            user: Username running process
            cpu_percent: CPU usage percentage
            memory_percent: Memory usage percentage
            connections: Number of network connections
            open_files: Number of open file handles
            children: Number of child processes
            timestamp: Event timestamp
            
        Returns:
            FeatureSet with extracted features
        """
        timestamp = timestamp or datetime.now()
        features = {}
        metadata = {'pid': pid, 'name': name, 'user': user}
        
        # Resource usage
        features['cpu_percent'] = min(cpu_percent / 100.0, 1.0)
        features['memory_percent'] = min(memory_percent / 100.0, 1.0)
        features['resource_total'] = (features['cpu_percent'] + features['memory_percent']) / 2
        
        # Process characteristics
        features['connection_count'] = min(connections / 100.0, 1.0)
        features['open_files_count'] = min(open_files / 1000.0, 1.0)
        features['children_count'] = min(children / 50.0, 1.0)
        
        # Name analysis
        features['name_length'] = len(name) / 50.0
        features['cmdline_length'] = len(cmdline) / 500.0
        
        # Suspicious indicators
        name_lower = name.lower()
        features['is_suspicious_name'] = 1.0 if name_lower in self.SUSPICIOUS_PROCESS_NAMES else 0.0
        features['has_suspicious_in_cmdline'] = 1.0 if any(
            s in cmdline.lower() for s in self.SUSPICIOUS_PROCESS_NAMES
        ) else 0.0
        
        # User context
        features['is_root'] = 1.0 if user in ('root', 'SYSTEM', 'Administrator') else 0.0
        features['is_service_account'] = 1.0 if user.startswith(('_', 'sys', 'daemon')) else 0.0
        
        # Command line analysis
        features['has_shell_operators'] = 1.0 if any(
            op in cmdline for op in ['|', '&&', '||', ';', '`', '$(']
        ) else 0.0
        features['has_redirection'] = 1.0 if any(
            op in cmdline for op in ['>', '>>', '<', '2>&1']
        ) else 0.0
        features['has_encoded_data'] = 1.0 if any(
            marker in cmdline.lower() for marker in ['base64', '-enc', '-e ']
        ) else 0.0
        
        # Network indicators
        features['has_network_args'] = 1.0 if any(
            arg in cmdline.lower() for arg in ['-p ', '--port', '::', 'http', 'tcp', 'udp']
        ) else 0.0
        
        # Time features
        features['hour_of_day'] = timestamp.hour / 24.0
        features['is_business_hours'] = 1.0 if 9 <= timestamp.hour <= 17 and timestamp.weekday() < 5 else 0.0
        
        return FeatureSet(
            timestamp=timestamp,
            source_type='process',
            features=features,
            metadata=metadata,
            raw_data={'pid': pid, 'name': name, 'cmdline': cmdline},
        )
    
    def extract_network_features(
        self,
        local_addr: str,
        local_port: int,
        remote_addr: str,
        remote_port: int,
        protocol: str,
        status: str,
        bytes_sent: int = 0,
        bytes_recv: int = 0,
        process_name: str = '',
        timestamp: Optional[datetime] = None,
    ) -> FeatureSet:
        """
        Extract features from network connection.
        
        Args:
            local_addr: Local IP address
            local_port: Local port
            remote_addr: Remote IP address
            remote_port: Remote port
            protocol: Protocol (TCP, UDP)
            status: Connection status
            bytes_sent: Bytes transmitted
            bytes_recv: Bytes received
            process_name: Associated process
            timestamp: Event timestamp
            
        Returns:
            FeatureSet with extracted features
        """
        timestamp = timestamp or datetime.now()
        features = {}
        metadata = {
            'local': f'{local_addr}:{local_port}',
            'remote': f'{remote_addr}:{remote_port}',
            'protocol': protocol,
        }
        
        # Port analysis
        features['local_port_normalized'] = min(local_port / 65535.0, 1.0)
        features['remote_port_normalized'] = min(remote_port / 65535.0, 1.0)
        features['is_privileged_local'] = 1.0 if local_port < 1024 else 0.0
        features['is_privileged_remote'] = 1.0 if remote_port < 1024 else 0.0
        features['is_common_port'] = 1.0 if remote_port in self.SAFE_PORTS else 0.0
        
        # High port connections (potential C2)
        features['is_high_port'] = 1.0 if remote_port > 10000 else 0.0
        
        # IP analysis
        features['is_local_loopback'] = 1.0 if local_addr.startswith('127.') else 0.0
        features['is_remote_loopback'] = 1.0 if remote_addr.startswith('127.') else 0.0
        features['is_remote_private'] = 1.0 if self._is_private_ip(remote_addr) else 0.0
        features['is_remote_public'] = 1.0 - features['is_remote_private'] - features['is_remote_loopback']
        
        # Protocol
        features['is_tcp'] = 1.0 if protocol.upper() == 'TCP' else 0.0
        features['is_udp'] = 1.0 if protocol.upper() == 'UDP' else 0.0
        
        # Connection status
        status_scores = {
            'established': 0.3,
            'listen': 0.2,
            'time_wait': 0.4,
            'close_wait': 0.5,
            'syn_sent': 0.6,
            'syn_recv': 0.5,
            'fin_wait': 0.4,
            'closing': 0.4,
        }
        features['status_score'] = status_scores.get(status.lower(), 0.3)
        
        # Data volume
        features['bytes_sent_normalized'] = min(bytes_sent / 1000000.0, 1.0)  # Normalize to 1MB
        features['bytes_recv_normalized'] = min(bytes_recv / 1000000.0, 1.0)
        features['data_ratio'] = bytes_sent / max(bytes_recv, 1) if bytes_recv > 0 else 1.0
        features['data_ratio_normalized'] = min(features['data_ratio'] / 10.0, 1.0)
        
        # Process association
        features['has_process'] = 1.0 if process_name else 0.0
        features['is_suspicious_process'] = 1.0 if process_name.lower() in self.SUSPICIOUS_PROCESS_NAMES else 0.0
        
        # Time features
        features['hour_of_day'] = timestamp.hour / 24.0
        features['is_business_hours'] = 1.0 if 9 <= timestamp.hour <= 17 and timestamp.weekday() < 5 else 0.0
        
        return FeatureSet(
            timestamp=timestamp,
            source_type='network',
            features=features,
            metadata=metadata,
            raw_data={
                'local': (local_addr, local_port),
                'remote': (remote_addr, remote_port),
                'protocol': protocol,
            },
        )
    
    def extract_metric_features(
        self,
        cpu_percent: float,
        memory_percent: float,
        disk_percent: float,
        disk_io_read: int = 0,
        disk_io_write: int = 0,
        net_bytes_sent: int = 0,
        net_bytes_recv: int = 0,
        process_count: int = 0,
        timestamp: Optional[datetime] = None,
    ) -> FeatureSet:
        """
        Extract features from system metrics.
        
        Args:
            cpu_percent: CPU usage percentage
            memory_percent: Memory usage percentage
            disk_percent: Disk usage percentage
            disk_io_read: Disk read bytes
            disk_io_write: Disk write bytes
            net_bytes_sent: Network bytes sent
            net_bytes_recv: Network bytes received
            process_count: Number of running processes
            timestamp: Event timestamp
            
        Returns:
            FeatureSet with extracted features
        """
        timestamp = timestamp or datetime.now()
        features = {}
        metadata = {}
        
        # Direct metrics (normalized)
        features['cpu_percent'] = cpu_percent / 100.0
        features['memory_percent'] = memory_percent / 100.0
        features['disk_percent'] = disk_percent / 100.0
        
        # Resource stress indicators
        features['high_cpu'] = 1.0 if cpu_percent > 80 else 0.0
        features['high_memory'] = 1.0 if memory_percent > 80 else 0.0
        features['high_disk'] = 1.0 if disk_percent > 90 else 0.0
        features['overall_stress'] = (features['high_cpu'] + features['high_memory'] + features['high_disk']) / 3.0
        
        # I/O metrics (normalized to reasonable maximums)
        features['disk_io_read_normalized'] = min(disk_io_read / (100 * 1024 * 1024), 1.0)  # 100MB
        features['disk_io_write_normalized'] = min(disk_io_write / (100 * 1024 * 1024), 1.0)
        features['disk_io_total'] = (features['disk_io_read_normalized'] + features['disk_io_write_normalized']) / 2
        
        features['net_bytes_sent_normalized'] = min(net_bytes_sent / (10 * 1024 * 1024), 1.0)  # 10MB
        features['net_bytes_recv_normalized'] = min(net_bytes_recv / (10 * 1024 * 1024), 1.0)
        features['net_total'] = (features['net_bytes_sent_normalized'] + features['net_bytes_recv_normalized']) / 2
        
        # Process count
        features['process_count_normalized'] = min(process_count / 500.0, 1.0)
        features['high_process_count'] = 1.0 if process_count > 300 else 0.0
        
        # Time features
        features['hour_of_day'] = timestamp.hour / 24.0
        features['is_business_hours'] = 1.0 if 9 <= timestamp.hour <= 17 and timestamp.weekday() < 5 else 0.0
        
        return FeatureSet(
            timestamp=timestamp,
            source_type='metric',
            features=features,
            metadata=metadata,
            raw_data={
                'cpu': cpu_percent,
                'memory': memory_percent,
                'disk': disk_percent,
            },
        )
    
    def _detect_severity(self, message: str) -> float:
        """Detect severity from message content."""
        message_lower = message.lower()
        for severity, score in sorted(self.SEVERITY_SCORES.items(), key=lambda x: -x[1]):
            if severity in message_lower:
                return score
        return 0.3  # Default
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range."""
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) != 4:
                return False
            return (
                parts[0] == 10 or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168) or
                parts[0] == 127
            )
        except:
            return False
    
    def _is_sensitive_path(self, path: str) -> bool:
        """Check if path is sensitive."""
        sensitive_patterns = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '.ssh', 'id_rsa', 'authorized_keys',
            '/root', '/home', 'C:\\Users',
            'password', 'secret', 'credential', 'token',
            '.env', 'config', '.git',
        ]
        path_lower = path.lower()
        return any(pattern in path_lower for pattern in sensitive_patterns)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        counter = Counter(text)
        length = len(text)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
        
        # Normalize to 0-1 range (max entropy for ASCII is ~6.6 bits)
        return min(entropy / 6.6, 1.0)
    
    @staticmethod
    def get_feature_names(source_type: str) -> List[str]:
        """Get ordered list of feature names for a source type."""
        # These should match the features extracted by each method
        if source_type == 'log':
            return [
                'message_length', 'word_count', 'uppercase_ratio', 'digit_ratio',
                'special_char_ratio', 'severity_score', 'hour_of_day', 'day_of_week',
                'is_business_hours', 'is_weekend', 'max_pattern_score', 'avg_pattern_score',
                'pattern_count', 'ip_count', 'has_private_ip', 'port_count',
                'has_unusual_port', 'path_count', 'has_sensitive_path',
                'source_sensitivity', 'entropy',
            ]
        elif source_type == 'process':
            return [
                'cpu_percent', 'memory_percent', 'resource_total', 'connection_count',
                'open_files_count', 'children_count', 'name_length', 'cmdline_length',
                'is_suspicious_name', 'has_suspicious_in_cmdline', 'is_root',
                'is_service_account', 'has_shell_operators', 'has_redirection',
                'has_encoded_data', 'has_network_args', 'hour_of_day', 'is_business_hours',
            ]
        elif source_type == 'network':
            return [
                'local_port_normalized', 'remote_port_normalized', 'is_privileged_local',
                'is_privileged_remote', 'is_common_port', 'is_high_port',
                'is_local_loopback', 'is_remote_loopback', 'is_remote_private',
                'is_remote_public', 'is_tcp', 'is_udp', 'status_score',
                'bytes_sent_normalized', 'bytes_recv_normalized', 'data_ratio_normalized',
                'has_process', 'is_suspicious_process', 'hour_of_day', 'is_business_hours',
            ]
        elif source_type == 'metric':
            return [
                'cpu_percent', 'memory_percent', 'disk_percent', 'high_cpu',
                'high_memory', 'high_disk', 'overall_stress', 'disk_io_read_normalized',
                'disk_io_write_normalized', 'disk_io_total', 'net_bytes_sent_normalized',
                'net_bytes_recv_normalized', 'net_total', 'process_count_normalized',
                'high_process_count', 'hour_of_day', 'is_business_hours',
            ]
        return []
