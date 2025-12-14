"""
ProjectLibra - System Monitor
Real-time system resource monitoring (CPU, Memory, Disk, Network)
"""

import psutil
import platform
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class SystemMetrics:
    """System resource metrics snapshot"""
    timestamp: str
    
    # CPU metrics
    cpu_percent: float
    cpu_count: int
    cpu_freq_current: float
    cpu_freq_max: float
    load_average: List[float]
    
    # Memory metrics
    memory_total: int
    memory_available: int
    memory_used: int
    memory_percent: float
    swap_total: int
    swap_used: int
    swap_percent: float
    
    # Disk metrics
    disk_total: int
    disk_used: int
    disk_free: int
    disk_percent: float
    disk_read_bytes: int
    disk_write_bytes: int
    
    # Network metrics
    network_bytes_sent: int
    network_bytes_recv: int
    network_packets_sent: int
    network_packets_recv: int
    
    # System info
    hostname: str
    platform: str
    kernel: str
    uptime_seconds: float
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def to_human_readable(self) -> Dict:
        """Convert to human-readable format"""
        return {
            'timestamp': self.timestamp,
            'cpu': {
                'usage': f"{self.cpu_percent}%",
                'cores': self.cpu_count,
                'frequency': f"{self.cpu_freq_current:.0f} / {self.cpu_freq_max:.0f} MHz",
                'load_avg': [f"{l:.2f}" for l in self.load_average],
            },
            'memory': {
                'used': self._bytes_to_human(self.memory_used),
                'total': self._bytes_to_human(self.memory_total),
                'available': self._bytes_to_human(self.memory_available),
                'percent': f"{self.memory_percent}%",
            },
            'swap': {
                'used': self._bytes_to_human(self.swap_used),
                'total': self._bytes_to_human(self.swap_total),
                'percent': f"{self.swap_percent}%",
            },
            'disk': {
                'used': self._bytes_to_human(self.disk_used),
                'free': self._bytes_to_human(self.disk_free),
                'total': self._bytes_to_human(self.disk_total),
                'percent': f"{self.disk_percent}%",
                'read': self._bytes_to_human(self.disk_read_bytes),
                'write': self._bytes_to_human(self.disk_write_bytes),
            },
            'network': {
                'sent': self._bytes_to_human(self.network_bytes_sent),
                'received': self._bytes_to_human(self.network_bytes_recv),
                'packets_sent': self.network_packets_sent,
                'packets_received': self.network_packets_recv,
            },
            'system': {
                'hostname': self.hostname,
                'platform': self.platform,
                'kernel': self.kernel,
                'uptime': self._seconds_to_human(self.uptime_seconds),
            }
        }
    
    @staticmethod
    def _bytes_to_human(bytes_val: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"
    
    @staticmethod
    def _seconds_to_human(seconds: float) -> str:
        """Convert seconds to human readable uptime"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{days}d {hours}h {minutes}m"


class SystemMonitor:
    """
    Real-time system resource monitor.
    
    Collects CPU, memory, disk, and network metrics.
    """
    
    def __init__(self):
        self.hostname = platform.node()
        self.platform_name = platform.system()
        self.kernel = platform.release()
        self._boot_time = psutil.boot_time()
        
        # Initialize counters
        self._disk_io_start = psutil.disk_io_counters()
        self._net_io_start = psutil.net_io_counters()
    
    def get_metrics(self) -> SystemMetrics:
        """Collect current system metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            try:
                load_avg = list(psutil.getloadavg())
            except AttributeError:
                # Windows doesn't have getloadavg
                load_avg = [0.0, 0.0, 0.0]
            
            # Memory metrics
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Disk metrics (root partition)
            disk = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            
            # Network metrics
            net_io = psutil.net_io_counters()
            
            # Uptime
            uptime = datetime.now().timestamp() - self._boot_time
            
            return SystemMetrics(
                timestamp=datetime.now().isoformat(),
                cpu_percent=cpu_percent,
                cpu_count=cpu_count,
                cpu_freq_current=cpu_freq.current if cpu_freq else 0,
                cpu_freq_max=cpu_freq.max if cpu_freq else 0,
                load_average=load_avg,
                memory_total=mem.total,
                memory_available=mem.available,
                memory_used=mem.used,
                memory_percent=mem.percent,
                swap_total=swap.total,
                swap_used=swap.used,
                swap_percent=swap.percent,
                disk_total=disk.total,
                disk_used=disk.used,
                disk_free=disk.free,
                disk_percent=disk.percent,
                disk_read_bytes=disk_io.read_bytes if disk_io else 0,
                disk_write_bytes=disk_io.write_bytes if disk_io else 0,
                network_bytes_sent=net_io.bytes_sent,
                network_bytes_recv=net_io.bytes_recv,
                network_packets_sent=net_io.packets_sent,
                network_packets_recv=net_io.packets_recv,
                hostname=self.hostname,
                platform=self.platform_name,
                kernel=self.kernel,
                uptime_seconds=uptime,
            )
        
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            raise
    
    def get_process_list(self, limit: int = 20, sort_by: str = 'cpu') -> List[Dict]:
        """Get top processes by resource usage"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cpu': proc.info['cpu_percent'] or 0,
                    'memory': proc.info['memory_percent'] or 0,
                    'status': proc.info['status'],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by specified metric
        if sort_by == 'cpu':
            processes.sort(key=lambda x: x['cpu'], reverse=True)
        elif sort_by == 'memory':
            processes.sort(key=lambda x: x['memory'], reverse=True)
        
        return processes[:limit]
    
    def get_disk_partitions(self) -> List[Dict]:
        """Get information about all disk partitions"""
        partitions = []
        
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                partitions.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': usage.percent,
                })
            except PermissionError:
                # Skip partitions we can't access
                continue
        
        return partitions
    
    def get_network_connections(self, limit: int = 50) -> List[Dict]:
        """Get active network connections"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet')[:limit]:
                connections.append({
                    'fd': conn.fd,
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'N/A',
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                    'status': conn.status,
                    'pid': conn.pid,
                })
        except (PermissionError, psutil.AccessDenied):
            logger.warning("Insufficient permissions to list network connections")
        
        return connections
