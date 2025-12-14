"""
ProjectLibra - Process Collector
Cross-platform process monitoring and collection
"""

import os
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
import hashlib

from .base_collector import BaseCollector, CollectedEvent

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available - process collection will be limited")


class ProcessCollector(BaseCollector):
    """
    Collects process information and monitors process lifecycle.
    Tracks process creation, termination, and behavior.
    """
    
    # Suspicious process indicators
    SUSPICIOUS_PATHS = [
        '/tmp/', '/dev/shm/', '/var/tmp/',
        'C:\\Temp\\', 'C:\\Users\\Public\\',
        '/home/', '\\AppData\\Local\\Temp\\'
    ]
    
    SUSPICIOUS_NAMES = [
        'nc', 'ncat', 'netcat', 'nmap', 'masscan',
        'mimikatz', 'pwdump', 'procdump',
        'powershell', 'cmd.exe', 'wscript', 'cscript',
        'python', 'perl', 'ruby', 'bash', 'sh'  # When spawned unexpectedly
    ]
    
    HIGH_RISK_PORTS = [4444, 5555, 6666, 1234, 31337, 12345]
    
    def __init__(self, 
                 host_id: Optional[str] = None,
                 track_children: bool = True,
                 monitor_network: bool = True):
        """
        Initialize the process collector.
        
        Args:
            host_id: Host identifier
            track_children: Track child process creation
            monitor_network: Monitor process network connections
        """
        super().__init__(host_id)
        self.track_children = track_children
        self.monitor_network = monitor_network
        self._known_pids: Set[int] = set()
        self._process_cache: Dict[int, Dict[str, Any]] = {}
        
        if PSUTIL_AVAILABLE:
            self._initialize_known_processes()
    
    def _initialize_known_processes(self):
        """Initialize the set of known processes"""
        try:
            for proc in psutil.process_iter(['pid']):
                self._known_pids.add(proc.info['pid'])
        except Exception as e:
            logger.error(f"Error initializing process list: {e}")
    
    def get_source_name(self) -> str:
        return "process_collector"
    
    def collect(self) -> List[CollectedEvent]:
        """Collect process events"""
        if not PSUTIL_AVAILABLE:
            return []
        
        events = []
        current_pids = set()
        
        try:
            for proc in psutil.process_iter([
                'pid', 'name', 'exe', 'cmdline', 'username',
                'create_time', 'ppid', 'status', 'cpu_percent',
                'memory_percent', 'num_threads', 'connections'
            ]):
                try:
                    pinfo = proc.info
                    pid = pinfo['pid']
                    current_pids.add(pid)
                    
                    # Check for new process
                    if pid not in self._known_pids:
                        event = self._create_process_event(proc, 'process_start')
                        if event:
                            events.append(event)
                        self._known_pids.add(pid)
                    
                    # Check for suspicious behavior
                    suspicious_event = self._check_suspicious_behavior(proc)
                    if suspicious_event:
                        events.append(suspicious_event)
                    
                    # Cache process info
                    self._process_cache[pid] = pinfo
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check for terminated processes
            terminated = self._known_pids - current_pids
            for pid in terminated:
                if pid in self._process_cache:
                    event = self._create_termination_event(pid)
                    if event:
                        events.append(event)
                    del self._process_cache[pid]
            
            self._known_pids = current_pids
            
        except Exception as e:
            logger.error(f"Error collecting processes: {e}")
        
        return events
    
    def _create_process_event(self, 
                               proc: 'psutil.Process', 
                               event_type: str) -> Optional[CollectedEvent]:
        """Create an event for a process"""
        try:
            pinfo = proc.as_dict(attrs=[
                'pid', 'name', 'exe', 'cmdline', 'username',
                'create_time', 'ppid', 'status', 'cwd',
                'cpu_percent', 'memory_percent', 'num_threads'
            ])
            
            # Get parent info
            parent_info = {}
            try:
                parent = proc.parent()
                if parent:
                    parent_info = {
                        'ppid': parent.pid,
                        'parent_name': parent.name(),
                        'parent_exe': parent.exe() if hasattr(parent, 'exe') else None
                    }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # Get network connections if monitoring
            connections = []
            if self.monitor_network:
                try:
                    for conn in proc.connections():
                        connections.append({
                            'fd': conn.fd,
                            'family': str(conn.family),
                            'type': str(conn.type),
                            'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                            'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                            'status': conn.status
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            raw_data = {
                'pid': pinfo['pid'],
                'name': pinfo['name'],
                'exe': pinfo['exe'],
                'cmdline': pinfo['cmdline'],
                'username': pinfo['username'],
                'create_time': pinfo['create_time'],
                'ppid': pinfo['ppid'],
                'status': pinfo['status'],
                'cwd': pinfo['cwd'],
                'cpu_percent': pinfo['cpu_percent'],
                'memory_percent': pinfo['memory_percent'],
                'num_threads': pinfo['num_threads'],
                'connections': connections,
                **parent_info
            }
            
            normalized = {
                'pid': pinfo['pid'],
                'name': pinfo['name'],
                'user': pinfo['username'],
                'parent_pid': pinfo['ppid'],
                'parent_name': parent_info.get('parent_name'),
                'command': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else pinfo['name'],
                'working_directory': pinfo['cwd'],
                'network_connections': len(connections),
                'cpu_usage': pinfo['cpu_percent'],
                'memory_usage': pinfo['memory_percent']
            }
            
            # Determine severity
            severity = self._assess_process_severity(pinfo, connections)
            
            # Extract tags
            tags = self._extract_process_tags(pinfo, connections)
            
            return self._create_event(
                event_type=event_type,
                severity=severity,
                raw_data=raw_data,
                normalized_data=normalized,
                tags=tags
            )
            
        except Exception as e:
            logger.error(f"Error creating process event: {e}")
            return None
    
    def _create_termination_event(self, pid: int) -> Optional[CollectedEvent]:
        """Create an event for a terminated process"""
        cached = self._process_cache.get(pid, {})
        
        raw_data = {
            'pid': pid,
            'name': cached.get('name', 'unknown'),
            'cached_info': cached
        }
        
        normalized = {
            'pid': pid,
            'name': cached.get('name', 'unknown'),
            'user': cached.get('username'),
            'action': 'termination'
        }
        
        return self._create_event(
            event_type='process_end',
            severity='info',
            raw_data=raw_data,
            normalized_data=normalized,
            tags=['process_lifecycle']
        )
    
    def _check_suspicious_behavior(self, proc: 'psutil.Process') -> Optional[CollectedEvent]:
        """Check for suspicious process behavior"""
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline', 'connections'])
            
            suspicious_indicators = []
            severity = 'info'
            
            # Check executable path
            exe = pinfo.get('exe') or ''
            for sus_path in self.SUSPICIOUS_PATHS:
                if sus_path.lower() in exe.lower():
                    suspicious_indicators.append(f"Executable in suspicious path: {sus_path}")
                    severity = 'warning'
            
            # Check process name
            name = pinfo.get('name', '').lower()
            for sus_name in self.SUSPICIOUS_NAMES:
                if sus_name.lower() in name:
                    suspicious_indicators.append(f"Suspicious process name: {name}")
                    severity = 'warning'
            
            # Check network connections for high-risk ports
            connections = pinfo.get('connections', [])
            for conn in connections:
                if hasattr(conn, 'raddr') and conn.raddr:
                    if conn.raddr.port in self.HIGH_RISK_PORTS:
                        suspicious_indicators.append(
                            f"Connection to high-risk port: {conn.raddr.port}"
                        )
                        severity = 'warning'
            
            # Check command line for suspicious patterns
            cmdline = ' '.join(pinfo.get('cmdline', []) or [])
            suspicious_cmdline_patterns = [
                'base64', 'eval', 'exec', 'wget', 'curl',
                '-e ', 'nc -', 'bash -i', 'python -c',
                'powershell -enc', 'IEX', 'Invoke-Expression'
            ]
            for pattern in suspicious_cmdline_patterns:
                if pattern.lower() in cmdline.lower():
                    suspicious_indicators.append(f"Suspicious command pattern: {pattern}")
                    severity = 'warning'
            
            if suspicious_indicators:
                return self._create_event(
                    event_type='suspicious_process',
                    severity=severity,
                    raw_data={
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'exe': pinfo['exe'],
                        'cmdline': pinfo['cmdline'],
                        'indicators': suspicious_indicators
                    },
                    normalized_data={
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'indicators': suspicious_indicators,
                        'risk_level': 'medium' if severity == 'warning' else 'low'
                    },
                    tags=['suspicious', 'security_event']
                )
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            logger.error(f"Error checking suspicious behavior: {e}")
        
        return None
    
    def _assess_process_severity(self, 
                                  pinfo: Dict[str, Any], 
                                  connections: List) -> str:
        """Assess severity of a process event"""
        # High CPU or memory usage
        if pinfo.get('cpu_percent', 0) > 80:
            return 'warning'
        if pinfo.get('memory_percent', 0) > 50:
            return 'warning'
        
        # Many network connections
        if len(connections) > 100:
            return 'warning'
        
        # Root/SYSTEM processes
        user = pinfo.get('username', '').lower()
        if user in ['root', 'system', 'nt authority\\system']:
            return 'info'  # Normal but notable
        
        return 'info'
    
    def _extract_process_tags(self, 
                               pinfo: Dict[str, Any], 
                               connections: List) -> List[str]:
        """Extract tags for a process"""
        tags = ['process']
        
        name = pinfo.get('name', '').lower()
        
        # Categorize by type
        if any(x in name for x in ['ssh', 'sshd']):
            tags.append('remote_access')
        if any(x in name for x in ['apache', 'nginx', 'httpd', 'iis']):
            tags.append('web_server')
        if any(x in name for x in ['mysql', 'postgres', 'mongo', 'redis']):
            tags.append('database')
        if any(x in name for x in ['docker', 'containerd', 'kubelet']):
            tags.append('container')
        
        # Network activity
        if connections:
            tags.append('network_active')
        
        return tags
    
    def get_process_tree(self, pid: int) -> Dict[str, Any]:
        """Get the process tree for a given PID"""
        if not PSUTIL_AVAILABLE:
            return {}
        
        try:
            proc = psutil.Process(pid)
            
            def get_children_recursive(p):
                children = []
                try:
                    for child in p.children():
                        children.append({
                            'pid': child.pid,
                            'name': child.name(),
                            'children': get_children_recursive(child)
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                return children
            
            return {
                'pid': proc.pid,
                'name': proc.name(),
                'children': get_children_recursive(proc)
            }
        except Exception as e:
            logger.error(f"Error getting process tree: {e}")
            return {}
    
    def get_all_processes(self) -> List[Dict[str, Any]]:
        """Get snapshot of all running processes"""
        if not PSUTIL_AVAILABLE:
            return []
        
        processes = []
        for proc in psutil.process_iter([
            'pid', 'name', 'username', 'cpu_percent', 
            'memory_percent', 'status'
        ]):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return processes
