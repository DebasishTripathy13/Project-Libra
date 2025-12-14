"""
Pattern Detection Module for Security Analysis.

Detects specific attack patterns, threat indicators,
and suspicious behavior sequences.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum
from collections import deque


class PatternCategory(Enum):
    """Categories of detected patterns."""
    AUTHENTICATION = 'authentication'
    RECONNAISSANCE = 'reconnaissance'
    EXPLOITATION = 'exploitation'
    PERSISTENCE = 'persistence'
    LATERAL_MOVEMENT = 'lateral_movement'
    EXFILTRATION = 'exfiltration'
    COMMAND_CONTROL = 'command_control'
    RESOURCE_ABUSE = 'resource_abuse'
    MALWARE = 'malware'
    POLICY_VIOLATION = 'policy_violation'


class MITRETactic(Enum):
    """MITRE ATT&CK Tactics."""
    INITIAL_ACCESS = 'TA0001'
    EXECUTION = 'TA0002'
    PERSISTENCE = 'TA0003'
    PRIVILEGE_ESCALATION = 'TA0004'
    DEFENSE_EVASION = 'TA0005'
    CREDENTIAL_ACCESS = 'TA0006'
    DISCOVERY = 'TA0007'
    LATERAL_MOVEMENT = 'TA0008'
    COLLECTION = 'TA0009'
    EXFILTRATION = 'TA0010'
    COMMAND_AND_CONTROL = 'TA0011'
    IMPACT = 'TA0040'


@dataclass
class PatternMatch:
    """Result of pattern matching."""
    
    pattern_name: str
    pattern_id: str
    category: PatternCategory
    confidence: float  # 0.0 to 1.0
    severity: float  # 0.0 to 1.0
    timestamp: datetime
    description: str
    evidence: List[str] = field(default_factory=list)
    mitre_tactics: List[MITRETactic] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'pattern_name': self.pattern_name,
            'pattern_id': self.pattern_id,
            'category': self.category.value,
            'confidence': self.confidence,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat(),
            'description': self.description,
            'evidence': self.evidence,
            'mitre_tactics': [t.value for t in self.mitre_tactics],
            'mitre_techniques': self.mitre_techniques,
            'recommended_actions': self.recommended_actions,
            'metadata': self.metadata,
        }


@dataclass
class PatternRule:
    """Definition of a detection pattern."""
    
    pattern_id: str
    name: str
    category: PatternCategory
    description: str
    severity: float
    
    # Matching criteria
    log_patterns: List[str] = field(default_factory=list)  # Regex patterns
    process_patterns: List[str] = field(default_factory=list)
    network_patterns: Dict[str, Any] = field(default_factory=dict)
    
    # Temporal requirements
    time_window_seconds: int = 300  # 5 minutes default
    min_occurrences: int = 1
    
    # MITRE mapping
    mitre_tactics: List[MITRETactic] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    # Response recommendations
    recommended_actions: List[str] = field(default_factory=list)


class PatternDetector:
    """
    Detects security patterns and attack indicators.
    
    Uses rule-based pattern matching combined with temporal
    correlation to detect complex attack patterns.
    """
    
    def __init__(self):
        """Initialize pattern detector with default rules."""
        self.rules: Dict[str, PatternRule] = {}
        self._event_history: deque = deque(maxlen=10000)
        self._ip_event_counts: Dict[str, int] = {}
        self._user_event_counts: Dict[str, int] = {}
        
        # Compiled regex patterns for efficiency
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        
        # Load default rules
        self._load_default_rules()
    
    def add_rule(self, rule: PatternRule) -> None:
        """Add a detection rule."""
        self.rules[rule.pattern_id] = rule
        
        # Compile log patterns
        if rule.log_patterns:
            self._compiled_patterns[rule.pattern_id] = [
                re.compile(p, re.IGNORECASE) for p in rule.log_patterns
            ]
    
    def detect_patterns(
        self,
        log_message: Optional[str] = None,
        process_info: Optional[Dict[str, Any]] = None,
        network_info: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
    ) -> List[PatternMatch]:
        """
        Detect patterns in provided data.
        
        Args:
            log_message: Log message to analyze
            process_info: Process information dict
            network_info: Network connection info dict
            timestamp: Event timestamp
            
        Returns:
            List of matched patterns
        """
        timestamp = timestamp or datetime.now()
        matches = []
        
        # Record event for temporal analysis
        self._record_event(timestamp, log_message, process_info, network_info)
        
        for rule_id, rule in self.rules.items():
            match = self._check_rule(rule, log_message, process_info, network_info, timestamp)
            if match:
                matches.append(match)
        
        return matches
    
    def detect_sequences(self, time_window: timedelta = timedelta(minutes=5)) -> List[PatternMatch]:
        """
        Detect attack sequences from event history.
        
        Looks for patterns that require multiple events.
        
        Args:
            time_window: Time window to analyze
            
        Returns:
            List of sequence-based pattern matches
        """
        matches = []
        now = datetime.now()
        cutoff = now - time_window
        
        # Get recent events
        recent_events = [
            e for e in self._event_history
            if e['timestamp'] >= cutoff
        ]
        
        if not recent_events:
            return matches
        
        # Check for brute force
        brute_force = self._detect_brute_force(recent_events, time_window)
        if brute_force:
            matches.append(brute_force)
        
        # Check for port scan
        port_scan = self._detect_port_scan(recent_events, time_window)
        if port_scan:
            matches.append(port_scan)
        
        # Check for data exfiltration
        exfil = self._detect_exfiltration(recent_events, time_window)
        if exfil:
            matches.append(exfil)
        
        return matches
    
    def _check_rule(
        self,
        rule: PatternRule,
        log_message: Optional[str],
        process_info: Optional[Dict],
        network_info: Optional[Dict],
        timestamp: datetime,
    ) -> Optional[PatternMatch]:
        """Check if a single rule matches."""
        evidence = []
        matched = False
        confidence = 0.0
        
        # Check log patterns
        if log_message and rule.pattern_id in self._compiled_patterns:
            for pattern in self._compiled_patterns[rule.pattern_id]:
                if pattern.search(log_message):
                    matched = True
                    evidence.append(f"Log matches: {pattern.pattern}")
                    confidence = max(confidence, 0.8)
        
        # Check process patterns
        if process_info and rule.process_patterns:
            cmdline = process_info.get('cmdline', '')
            name = process_info.get('name', '')
            
            for pattern in rule.process_patterns:
                regex = re.compile(pattern, re.IGNORECASE)
                if regex.search(cmdline) or regex.search(name):
                    matched = True
                    evidence.append(f"Process matches: {pattern}")
                    confidence = max(confidence, 0.85)
        
        # Check network patterns
        if network_info and rule.network_patterns:
            net_matched, net_evidence = self._check_network_pattern(
                network_info, rule.network_patterns
            )
            if net_matched:
                matched = True
                evidence.extend(net_evidence)
                confidence = max(confidence, 0.75)
        
        if not matched:
            return None
        
        # Check temporal requirements (if more than 1 occurrence required)
        if rule.min_occurrences > 1:
            occurrences = self._count_recent_pattern_matches(
                rule, timedelta(seconds=rule.time_window_seconds)
            )
            if occurrences < rule.min_occurrences:
                return None
            evidence.append(f"Pattern occurred {occurrences} times in window")
            confidence = min(confidence + 0.1, 1.0)
        
        return PatternMatch(
            pattern_name=rule.name,
            pattern_id=rule.pattern_id,
            category=rule.category,
            confidence=confidence,
            severity=rule.severity,
            timestamp=timestamp,
            description=rule.description,
            evidence=evidence,
            mitre_tactics=rule.mitre_tactics,
            mitre_techniques=rule.mitre_techniques,
            recommended_actions=rule.recommended_actions,
        )
    
    def _check_network_pattern(
        self,
        network_info: Dict,
        pattern: Dict,
    ) -> Tuple[bool, List[str]]:
        """Check network-specific patterns."""
        evidence = []
        matched = False
        
        # Check port ranges
        if 'port_ranges' in pattern:
            remote_port = network_info.get('remote_port', 0)
            for port_range in pattern['port_ranges']:
                if port_range[0] <= remote_port <= port_range[1]:
                    matched = True
                    evidence.append(f"Port {remote_port} in suspicious range")
        
        # Check for specific ports
        if 'suspicious_ports' in pattern:
            remote_port = network_info.get('remote_port', 0)
            if remote_port in pattern['suspicious_ports']:
                matched = True
                evidence.append(f"Connection to suspicious port {remote_port}")
        
        # Check for public IP connections
        if pattern.get('requires_public_ip'):
            remote_addr = network_info.get('remote_addr', '')
            if not self._is_private_ip(remote_addr):
                matched = True
                evidence.append(f"Connection to public IP {remote_addr}")
        
        return matched, evidence
    
    def _record_event(
        self,
        timestamp: datetime,
        log_message: Optional[str],
        process_info: Optional[Dict],
        network_info: Optional[Dict],
    ) -> None:
        """Record event for temporal analysis."""
        event = {
            'timestamp': timestamp,
            'log_message': log_message,
            'process_info': process_info,
            'network_info': network_info,
        }
        self._event_history.append(event)
        
        # Track IP-based events
        if network_info:
            ip = network_info.get('remote_addr', '')
            if ip:
                self._ip_event_counts[ip] = self._ip_event_counts.get(ip, 0) + 1
    
    def _count_recent_pattern_matches(
        self,
        rule: PatternRule,
        window: timedelta,
    ) -> int:
        """Count pattern matches in time window."""
        # Simplified counting - in production would track per-rule
        now = datetime.now()
        cutoff = now - window
        
        count = 0
        for event in self._event_history:
            if event['timestamp'] < cutoff:
                continue
            
            # Check if event matches rule patterns
            if event['log_message'] and rule.pattern_id in self._compiled_patterns:
                for pattern in self._compiled_patterns[rule.pattern_id]:
                    if pattern.search(event['log_message']):
                        count += 1
                        break
        
        return count
    
    def _detect_brute_force(
        self,
        events: List[Dict],
        window: timedelta,
    ) -> Optional[PatternMatch]:
        """Detect brute force attack pattern."""
        auth_failures = []
        
        for event in events:
            msg = event.get('log_message', '') or ''
            if any(p in msg.lower() for p in ['failed password', 'authentication failure', 'invalid user']):
                auth_failures.append(event)
        
        if len(auth_failures) >= 5:  # 5 failures in window
            return PatternMatch(
                pattern_name="Brute Force Attack",
                pattern_id="SEQ-001",
                category=PatternCategory.AUTHENTICATION,
                confidence=min(0.5 + len(auth_failures) * 0.05, 0.95),
                severity=0.8,
                timestamp=datetime.now(),
                description=f"Detected {len(auth_failures)} authentication failures in {window}",
                evidence=[f"Authentication failures: {len(auth_failures)}"],
                mitre_tactics=[MITRETactic.CREDENTIAL_ACCESS, MITRETactic.INITIAL_ACCESS],
                mitre_techniques=['T1110', 'T1110.001', 'T1110.003'],
                recommended_actions=[
                    "Review source IPs and consider blocking",
                    "Enable account lockout policies",
                    "Implement multi-factor authentication",
                    "Check for compromised credentials",
                ],
            )
        
        return None
    
    def _detect_port_scan(
        self,
        events: List[Dict],
        window: timedelta,
    ) -> Optional[PatternMatch]:
        """Detect port scanning activity."""
        source_ports: Dict[str, Set[int]] = {}
        
        for event in events:
            net_info = event.get('network_info')
            if not net_info:
                continue
            
            remote_addr = net_info.get('remote_addr', '')
            local_port = net_info.get('local_port', 0)
            
            if remote_addr:
                if remote_addr not in source_ports:
                    source_ports[remote_addr] = set()
                source_ports[remote_addr].add(local_port)
        
        # Check for IP touching many ports
        for ip, ports in source_ports.items():
            if len(ports) >= 10:  # 10 different ports
                return PatternMatch(
                    pattern_name="Port Scan Detected",
                    pattern_id="SEQ-002",
                    category=PatternCategory.RECONNAISSANCE,
                    confidence=min(0.6 + len(ports) * 0.02, 0.95),
                    severity=0.6,
                    timestamp=datetime.now(),
                    description=f"IP {ip} accessed {len(ports)} different ports",
                    evidence=[
                        f"Source IP: {ip}",
                        f"Unique ports: {len(ports)}",
                        f"Sample ports: {list(ports)[:10]}",
                    ],
                    mitre_tactics=[MITRETactic.DISCOVERY],
                    mitre_techniques=['T1046'],
                    recommended_actions=[
                        f"Block or monitor IP {ip}",
                        "Review firewall rules",
                        "Check for successful connections",
                    ],
                )
        
        return None
    
    def _detect_exfiltration(
        self,
        events: List[Dict],
        window: timedelta,
    ) -> Optional[PatternMatch]:
        """Detect potential data exfiltration."""
        # This would analyze data transfer patterns
        # Simplified check for large outbound transfers
        
        outbound_bytes = 0
        destinations: Set[str] = set()
        
        for event in events:
            net_info = event.get('network_info')
            if not net_info:
                continue
            
            remote_addr = net_info.get('remote_addr', '')
            bytes_sent = net_info.get('bytes_sent', 0)
            
            if remote_addr and not self._is_private_ip(remote_addr):
                outbound_bytes += bytes_sent
                destinations.add(remote_addr)
        
        # Alert on large outbound transfers to multiple destinations
        if outbound_bytes > 100 * 1024 * 1024 and len(destinations) > 3:  # 100MB to 3+ destinations
            return PatternMatch(
                pattern_name="Potential Data Exfiltration",
                pattern_id="SEQ-003",
                category=PatternCategory.EXFILTRATION,
                confidence=0.7,
                severity=0.9,
                timestamp=datetime.now(),
                description=f"Large outbound transfer ({outbound_bytes / 1024 / 1024:.1f}MB) to {len(destinations)} destinations",
                evidence=[
                    f"Total bytes: {outbound_bytes}",
                    f"Destination count: {len(destinations)}",
                ],
                mitre_tactics=[MITRETactic.EXFILTRATION],
                mitre_techniques=['T1041', 'T1048'],
                recommended_actions=[
                    "Review destination IPs",
                    "Check for unauthorized data access",
                    "Analyze transferred content if possible",
                    "Investigate source processes",
                ],
            )
        
        return None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private."""
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
    
    def _load_default_rules(self) -> None:
        """Load default detection rules."""
        
        # Authentication-related rules
        self.add_rule(PatternRule(
            pattern_id="AUTH-001",
            name="SSH Brute Force Attempt",
            category=PatternCategory.AUTHENTICATION,
            description="Multiple SSH authentication failures detected",
            severity=0.8,
            log_patterns=[
                r'sshd.*failed password',
                r'sshd.*invalid user',
                r'sshd.*authentication failure',
            ],
            min_occurrences=3,
            time_window_seconds=300,
            mitre_tactics=[MITRETactic.CREDENTIAL_ACCESS, MITRETactic.INITIAL_ACCESS],
            mitre_techniques=['T1110', 'T1110.001'],
            recommended_actions=[
                "Review source IP addresses",
                "Consider implementing fail2ban",
                "Enable SSH key-based authentication",
            ],
        ))
        
        self.add_rule(PatternRule(
            pattern_id="AUTH-002",
            name="Root Login Attempt",
            category=PatternCategory.AUTHENTICATION,
            description="Direct root login attempt detected",
            severity=0.7,
            log_patterns=[
                r'sshd.*root.*accepted',
                r'login.*root.*success',
                r'su.*root',
            ],
            mitre_tactics=[MITRETactic.PRIVILEGE_ESCALATION],
            mitre_techniques=['T1078.003'],
            recommended_actions=[
                "Verify if root login is expected",
                "Disable direct root SSH access",
                "Implement sudo policies",
            ],
        ))
        
        # Reconnaissance rules
        self.add_rule(PatternRule(
            pattern_id="RECON-001",
            name="Network Enumeration",
            category=PatternCategory.RECONNAISSANCE,
            description="Network scanning or enumeration tools detected",
            severity=0.6,
            process_patterns=[
                r'nmap',
                r'masscan',
                r'zmap',
                r'netdiscover',
                r'arp-scan',
            ],
            mitre_tactics=[MITRETactic.DISCOVERY],
            mitre_techniques=['T1046', 'T1040'],
            recommended_actions=[
                "Verify if scan is authorized",
                "Review source user and system",
                "Check for compromised systems",
            ],
        ))
        
        # Exploitation rules
        self.add_rule(PatternRule(
            pattern_id="EXPLOIT-001",
            name="Reverse Shell Indicator",
            category=PatternCategory.EXPLOITATION,
            description="Potential reverse shell connection detected",
            severity=0.95,
            process_patterns=[
                r'nc\s+-e',
                r'bash\s+-i\s+>&',
                r'/dev/tcp/',
                r'mkfifo.*nc',
                r'python.*socket.*connect',
            ],
            log_patterns=[
                r'reverse shell',
                r'connect back',
            ],
            mitre_tactics=[MITRETactic.EXECUTION, MITRETactic.COMMAND_AND_CONTROL],
            mitre_techniques=['T1059', 'T1071'],
            recommended_actions=[
                "Immediately isolate affected system",
                "Capture forensic evidence",
                "Identify and block C2 IP",
                "Initiate incident response",
            ],
        ))
        
        # Persistence rules
        self.add_rule(PatternRule(
            pattern_id="PERSIST-001",
            name="Cron Job Modification",
            category=PatternCategory.PERSISTENCE,
            description="System cron job modification detected",
            severity=0.7,
            log_patterns=[
                r'crontab.*modified',
                r'CROND.*CMD',
                r'/etc/cron',
            ],
            process_patterns=[
                r'crontab\s+-[ei]',
            ],
            mitre_tactics=[MITRETactic.PERSISTENCE],
            mitre_techniques=['T1053.003'],
            recommended_actions=[
                "Review cron job changes",
                "Compare with baseline configuration",
                "Check for unauthorized entries",
            ],
        ))
        
        # Malware indicators
        self.add_rule(PatternRule(
            pattern_id="MALWARE-001",
            name="Cryptominer Indicators",
            category=PatternCategory.MALWARE,
            description="Cryptocurrency mining activity detected",
            severity=0.8,
            process_patterns=[
                r'xmrig',
                r'minerd',
                r'cpuminer',
                r'stratum\+tcp',
                r'nicehash',
            ],
            log_patterns=[
                r'mining pool',
                r'stratum',
                r'cryptonight',
            ],
            mitre_tactics=[MITRETactic.IMPACT],
            mitre_techniques=['T1496'],
            recommended_actions=[
                "Kill mining processes",
                "Check for persistence mechanisms",
                "Review initial access vector",
                "Check for other compromised systems",
            ],
        ))
        
        # Command and Control
        self.add_rule(PatternRule(
            pattern_id="C2-001",
            name="Suspicious Outbound Connection",
            category=PatternCategory.COMMAND_CONTROL,
            description="Connection to suspicious high-numbered port on public IP",
            severity=0.6,
            network_patterns={
                'port_ranges': [(8080, 8090), (4443, 4445), (9000, 9999)],
                'requires_public_ip': True,
            },
            mitre_tactics=[MITRETactic.COMMAND_AND_CONTROL],
            mitre_techniques=['T1571', 'T1071'],
            recommended_actions=[
                "Investigate destination IP reputation",
                "Review process making connection",
                "Check for data exfiltration",
            ],
        ))
        
        # Resource abuse
        self.add_rule(PatternRule(
            pattern_id="ABUSE-001",
            name="Resource Exhaustion",
            category=PatternCategory.RESOURCE_ABUSE,
            description="System resource exhaustion detected",
            severity=0.6,
            log_patterns=[
                r'out of memory',
                r'oom[-_]killer',
                r'no space left',
                r'fork\(\) failed',
            ],
            mitre_tactics=[MITRETactic.IMPACT],
            mitre_techniques=['T1499'],
            recommended_actions=[
                "Identify resource-consuming processes",
                "Check for DoS attack indicators",
                "Review system limits",
            ],
        ))
