"""
ProjectLibra - Network Collector
Cross-platform network activity monitoring
"""

import logging
import socket
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict
import math

from .base_collector import BaseCollector, CollectedEvent

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class NetworkCollector(BaseCollector):
    """
    Collects network activity information.
    Monitors connections, traffic patterns, and detects anomalies.
    """
    
    # Known suspicious ports
    SUSPICIOUS_PORTS = {
        4444: 'metasploit_default',
        5555: 'common_backdoor',
        6666: 'irc_backdoor',
        31337: 'elite_backdoor',
        12345: 'netbus',
        1234: 'common_rat',
        8080: 'http_alt',
        3389: 'rdp',
        22: 'ssh',
        23: 'telnet',
        445: 'smb',
        135: 'rpc',
        139: 'netbios'
    }
    
    # High-risk destination patterns
    HIGH_RISK_RANGES = [
        ('10.0.0.0', '10.255.255.255'),      # Private - internal lateral movement
        ('192.168.0.0', '192.168.255.255'),  # Private - internal lateral movement  
        ('172.16.0.0', '172.31.255.255'),    # Private - internal lateral movement
    ]
    
    def __init__(self,
                 host_id: Optional[str] = None,
                 monitor_interval: int = 5,
                 track_bandwidth: bool = True):
        """
        Initialize the network collector.
        
        Args:
            host_id: Host identifier
            monitor_interval: Monitoring interval in seconds
            track_bandwidth: Track bandwidth usage
        """
        super().__init__(host_id)
        self.monitor_interval = monitor_interval
        self.track_bandwidth = track_bandwidth
        
        self._known_connections: Set[tuple] = set()
        self._connection_history: Dict[str, List[Dict]] = defaultdict(list)
        self._last_io_counters: Optional[Dict] = None
        self._dns_cache: Dict[str, str] = {}
    
    def get_source_name(self) -> str:
        return "network_collector"
    
    def collect(self) -> List[CollectedEvent]:
        """Collect network events"""
        if not PSUTIL_AVAILABLE:
            return []
        
        events = []
        
        try:
            # Collect connection events
            events.extend(self._collect_connections())
            
            # Collect bandwidth metrics
            if self.track_bandwidth:
                bandwidth_event = self._collect_bandwidth()
                if bandwidth_event:
                    events.append(bandwidth_event)
            
            # Collect interface info
            interface_event = self._collect_interface_info()
            if interface_event:
                events.append(interface_event)
            
        except Exception as e:
            logger.error(f"Error collecting network data: {e}")
        
        return events
    
    def _collect_connections(self) -> List[CollectedEvent]:
        """Collect active network connections"""
        events = []
        current_connections = set()
        
        try:
            connections = psutil.net_connections(kind='all')
            
            for conn in connections:
                # Create connection tuple for tracking
                conn_tuple = (
                    conn.laddr.ip if conn.laddr else None,
                    conn.laddr.port if conn.laddr else None,
                    conn.raddr.ip if conn.raddr else None,
                    conn.raddr.port if conn.raddr else None,
                    conn.status,
                    conn.pid
                )
                current_connections.add(conn_tuple)
                
                # New connection detected
                if conn_tuple not in self._known_connections:
                    event = self._create_connection_event(conn)
                    if event:
                        events.append(event)
                    
                    # Check for suspicious connection
                    suspicious_event = self._check_suspicious_connection(conn)
                    if suspicious_event:
                        events.append(suspicious_event)
            
            # Track closed connections
            closed = self._known_connections - current_connections
            for conn_tuple in closed:
                event = self._create_closed_connection_event(conn_tuple)
                if event:
                    events.append(event)
            
            self._known_connections = current_connections
            
        except Exception as e:
            logger.error(f"Error collecting connections: {e}")
        
        return events
    
    def _create_connection_event(self, conn) -> Optional[CollectedEvent]:
        """Create event for a new connection"""
        try:
            # Get process info
            process_name = None
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    process_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Resolve hostname if possible
            remote_host = None
            if conn.raddr:
                remote_host = self._resolve_hostname(conn.raddr.ip)
            
            raw_data = {
                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                'status': conn.status,
                'pid': conn.pid,
                'family': str(conn.family),
                'type': str(conn.type),
                'process_name': process_name
            }
            
            normalized = {
                'local_ip': conn.laddr.ip if conn.laddr else None,
                'local_port': conn.laddr.port if conn.laddr else None,
                'remote_ip': conn.raddr.ip if conn.raddr else None,
                'remote_port': conn.raddr.port if conn.raddr else None,
                'remote_host': remote_host,
                'status': conn.status,
                'pid': conn.pid,
                'process': process_name,
                'direction': self._determine_direction(conn)
            }
            
            # Determine severity
            severity = self._assess_connection_severity(conn, process_name)
            
            # Extract tags
            tags = self._extract_connection_tags(conn, process_name)
            
            return self._create_event(
                event_type='network_connection',
                severity=severity,
                raw_data=raw_data,
                normalized_data=normalized,
                tags=tags
            )
            
        except Exception as e:
            logger.error(f"Error creating connection event: {e}")
            return None
    
    def _create_closed_connection_event(self, conn_tuple: tuple) -> Optional[CollectedEvent]:
        """Create event for a closed connection"""
        local_ip, local_port, remote_ip, remote_port, status, pid = conn_tuple
        
        raw_data = {
            'local_address': f"{local_ip}:{local_port}" if local_ip else None,
            'remote_address': f"{remote_ip}:{remote_port}" if remote_ip else None,
            'previous_status': status,
            'pid': pid
        }
        
        normalized = {
            'local_ip': local_ip,
            'local_port': local_port,
            'remote_ip': remote_ip,
            'remote_port': remote_port,
            'pid': pid,
            'action': 'closed'
        }
        
        return self._create_event(
            event_type='connection_closed',
            severity='info',
            raw_data=raw_data,
            normalized_data=normalized,
            tags=['network', 'connection_lifecycle']
        )
    
    def _check_suspicious_connection(self, conn) -> Optional[CollectedEvent]:
        """Check for suspicious network connections"""
        indicators = []
        severity = 'info'
        
        # Check remote port
        if conn.raddr:
            port = conn.raddr.port
            if port in self.SUSPICIOUS_PORTS:
                indicators.append(f"Connection to suspicious port {port} ({self.SUSPICIOUS_PORTS[port]})")
                severity = 'warning'
        
        # Check for connections to unusual ports
        if conn.raddr and conn.raddr.port:
            if conn.raddr.port > 49152:  # Dynamic/private ports
                indicators.append(f"Connection to high port {conn.raddr.port}")
        
        # Calculate connection entropy (for detecting C2 beaconing)
        if conn.raddr:
            entropy = self._calculate_ip_entropy(conn.raddr.ip)
            if entropy > 3.5:  # High entropy might indicate generated domain/IP
                indicators.append(f"High entropy remote IP: {entropy:.2f}")
        
        # Check for potential data exfiltration (many outbound connections)
        if conn.pid:
            conn_count = self._count_process_connections(conn.pid)
            if conn_count > 50:
                indicators.append(f"Process has {conn_count} connections (potential exfiltration)")
                severity = 'warning'
        
        if indicators:
            process_name = None
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    process_name = proc.name()
                except:
                    pass
            
            return self._create_event(
                event_type='suspicious_connection',
                severity=severity,
                raw_data={
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'pid': conn.pid,
                    'process': process_name,
                    'indicators': indicators
                },
                normalized_data={
                    'remote_ip': conn.raddr.ip if conn.raddr else None,
                    'remote_port': conn.raddr.port if conn.raddr else None,
                    'pid': conn.pid,
                    'process': process_name,
                    'indicators': indicators,
                    'risk_score': len(indicators) * 25
                },
                tags=['suspicious', 'security_event', 'network']
            )
        
        return None
    
    def _collect_bandwidth(self) -> Optional[CollectedEvent]:
        """Collect bandwidth usage metrics"""
        try:
            counters = psutil.net_io_counters()
            
            if self._last_io_counters:
                # Calculate delta
                bytes_sent = counters.bytes_sent - self._last_io_counters['bytes_sent']
                bytes_recv = counters.bytes_recv - self._last_io_counters['bytes_recv']
                packets_sent = counters.packets_sent - self._last_io_counters['packets_sent']
                packets_recv = counters.packets_recv - self._last_io_counters['packets_recv']
                
                raw_data = {
                    'bytes_sent': counters.bytes_sent,
                    'bytes_recv': counters.bytes_recv,
                    'packets_sent': counters.packets_sent,
                    'packets_recv': counters.packets_recv,
                    'errin': counters.errin,
                    'errout': counters.errout,
                    'dropin': counters.dropin,
                    'dropout': counters.dropout,
                    'delta_bytes_sent': bytes_sent,
                    'delta_bytes_recv': bytes_recv
                }
                
                normalized = {
                    'bytes_sent_per_sec': bytes_sent / self.monitor_interval,
                    'bytes_recv_per_sec': bytes_recv / self.monitor_interval,
                    'packets_sent_per_sec': packets_sent / self.monitor_interval,
                    'packets_recv_per_sec': packets_recv / self.monitor_interval,
                    'total_bandwidth_mbps': (bytes_sent + bytes_recv) * 8 / 1_000_000 / self.monitor_interval
                }
                
                # Check for unusual bandwidth
                severity = 'info'
                if normalized['total_bandwidth_mbps'] > 100:
                    severity = 'warning'
                
                self._last_io_counters = {
                    'bytes_sent': counters.bytes_sent,
                    'bytes_recv': counters.bytes_recv,
                    'packets_sent': counters.packets_sent,
                    'packets_recv': counters.packets_recv
                }
                
                return self._create_event(
                    event_type='bandwidth_metrics',
                    severity=severity,
                    raw_data=raw_data,
                    normalized_data=normalized,
                    tags=['metrics', 'bandwidth']
                )
            else:
                self._last_io_counters = {
                    'bytes_sent': counters.bytes_sent,
                    'bytes_recv': counters.bytes_recv,
                    'packets_sent': counters.packets_sent,
                    'packets_recv': counters.packets_recv
                }
            
        except Exception as e:
            logger.error(f"Error collecting bandwidth: {e}")
        
        return None
    
    def _collect_interface_info(self) -> Optional[CollectedEvent]:
        """Collect network interface information"""
        try:
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            interface_data = {}
            for name, addrs in interfaces.items():
                interface_data[name] = {
                    'addresses': [
                        {
                            'family': str(addr.family),
                            'address': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast
                        }
                        for addr in addrs
                    ],
                    'is_up': stats[name].isup if name in stats else False,
                    'speed': stats[name].speed if name in stats else 0
                }
            
            return self._create_event(
                event_type='interface_status',
                severity='info',
                raw_data={'interfaces': interface_data},
                normalized_data={
                    'interface_count': len(interface_data),
                    'active_interfaces': sum(1 for i in interface_data.values() if i['is_up'])
                },
                tags=['network', 'interfaces']
            )
            
        except Exception as e:
            logger.error(f"Error collecting interface info: {e}")
            return None
    
    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve IP to hostname with caching"""
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self._dns_cache[ip] = hostname
            return hostname
        except (socket.herror, socket.gaierror):
            self._dns_cache[ip] = None
            return None
    
    def _determine_direction(self, conn) -> str:
        """Determine connection direction"""
        if conn.status == 'LISTEN':
            return 'listen'
        elif conn.raddr:
            return 'outbound'
        else:
            return 'inbound'
    
    def _assess_connection_severity(self, conn, process_name: Optional[str]) -> str:
        """Assess severity of a connection"""
        if conn.raddr and conn.raddr.port in self.SUSPICIOUS_PORTS:
            return 'warning'
        
        # Check for unusual processes with network activity
        suspicious_processes = ['nc', 'netcat', 'ncat', 'nmap']
        if process_name and any(sp in process_name.lower() for sp in suspicious_processes):
            return 'warning'
        
        return 'info'
    
    def _extract_connection_tags(self, conn, process_name: Optional[str]) -> List[str]:
        """Extract tags for a connection"""
        tags = ['network', 'connection']
        
        if conn.raddr:
            port = conn.raddr.port
            if port == 80:
                tags.append('http')
            elif port == 443:
                tags.append('https')
            elif port == 22:
                tags.append('ssh')
            elif port == 3389:
                tags.append('rdp')
            elif port in self.SUSPICIOUS_PORTS:
                tags.append('suspicious_port')
        
        if conn.status == 'ESTABLISHED':
            tags.append('established')
        elif conn.status == 'LISTEN':
            tags.append('listening')
        
        return tags
    
    def _calculate_ip_entropy(self, ip: str) -> float:
        """Calculate Shannon entropy of an IP address"""
        if not ip:
            return 0.0
        
        freq = {}
        for char in ip:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            p = count / len(ip)
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _count_process_connections(self, pid: int) -> int:
        """Count connections for a process"""
        count = 0
        for conn_tuple in self._known_connections:
            if conn_tuple[5] == pid:  # pid is at index 5
                count += 1
        return count
    
    def get_connection_summary(self) -> Dict[str, Any]:
        """Get summary of current connections"""
        if not PSUTIL_AVAILABLE:
            return {}
        
        connections = psutil.net_connections(kind='inet')
        
        summary = {
            'total': len(connections),
            'established': 0,
            'listening': 0,
            'time_wait': 0,
            'close_wait': 0,
            'by_process': defaultdict(int),
            'by_remote_port': defaultdict(int)
        }
        
        for conn in connections:
            if conn.status == 'ESTABLISHED':
                summary['established'] += 1
            elif conn.status == 'LISTEN':
                summary['listening'] += 1
            elif conn.status == 'TIME_WAIT':
                summary['time_wait'] += 1
            elif conn.status == 'CLOSE_WAIT':
                summary['close_wait'] += 1
            
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    summary['by_process'][proc.name()] += 1
                except:
                    pass
            
            if conn.raddr:
                summary['by_remote_port'][conn.raddr.port] += 1
        
        summary['by_process'] = dict(summary['by_process'])
        summary['by_remote_port'] = dict(summary['by_remote_port'])
        
        return summary
