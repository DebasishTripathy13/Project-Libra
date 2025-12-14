"""
ProjectLibra - Metrics Collector
System metrics collection (CPU, Memory, Disk, I/O)
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
import time

from .base_collector import BaseCollector, CollectedEvent

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class MetricsCollector(BaseCollector):
    """
    Collects system performance metrics.
    Used for behavioral baseline and anomaly detection.
    """
    
    # Thresholds for alerts
    CPU_WARNING_THRESHOLD = 80.0
    CPU_CRITICAL_THRESHOLD = 95.0
    MEMORY_WARNING_THRESHOLD = 85.0
    MEMORY_CRITICAL_THRESHOLD = 95.0
    DISK_WARNING_THRESHOLD = 85.0
    DISK_CRITICAL_THRESHOLD = 95.0
    
    def __init__(self,
                 host_id: Optional[str] = None,
                 collect_per_cpu: bool = False,
                 collect_disk_io: bool = True,
                 collect_temperatures: bool = False):
        """
        Initialize the metrics collector.
        
        Args:
            host_id: Host identifier
            collect_per_cpu: Collect per-CPU metrics
            collect_disk_io: Collect disk I/O metrics
            collect_temperatures: Collect temperature sensors
        """
        super().__init__(host_id)
        self.collect_per_cpu = collect_per_cpu
        self.collect_disk_io = collect_disk_io
        self.collect_temperatures = collect_temperatures
        
        self._last_disk_io: Optional[Dict] = None
        self._last_collect_time: Optional[float] = None
    
    def get_source_name(self) -> str:
        return "metrics_collector"
    
    def collect(self) -> List[CollectedEvent]:
        """Collect all system metrics"""
        if not PSUTIL_AVAILABLE:
            return []
        
        events = []
        
        try:
            # CPU metrics
            cpu_event = self._collect_cpu_metrics()
            if cpu_event:
                events.append(cpu_event)
            
            # Memory metrics
            memory_event = self._collect_memory_metrics()
            if memory_event:
                events.append(memory_event)
            
            # Disk metrics
            disk_event = self._collect_disk_metrics()
            if disk_event:
                events.append(disk_event)
            
            # Disk I/O
            if self.collect_disk_io:
                io_event = self._collect_disk_io()
                if io_event:
                    events.append(io_event)
            
            # System load
            load_event = self._collect_load_average()
            if load_event:
                events.append(load_event)
            
            # Temperatures
            if self.collect_temperatures:
                temp_event = self._collect_temperatures()
                if temp_event:
                    events.append(temp_event)
            
            # Combined system health
            health_event = self._create_health_summary(events)
            if health_event:
                events.append(health_event)
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
        
        return events
    
    def _collect_cpu_metrics(self) -> Optional[CollectedEvent]:
        """Collect CPU metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_times = psutil.cpu_times_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            cpu_count_logical = psutil.cpu_count(logical=True)
            
            raw_data = {
                'cpu_percent': cpu_percent,
                'cpu_count': cpu_count,
                'cpu_count_logical': cpu_count_logical,
                'cpu_times': {
                    'user': cpu_times.user,
                    'system': cpu_times.system,
                    'idle': cpu_times.idle,
                    'iowait': getattr(cpu_times, 'iowait', 0),
                    'irq': getattr(cpu_times, 'irq', 0),
                    'softirq': getattr(cpu_times, 'softirq', 0)
                }
            }
            
            # Per-CPU metrics
            if self.collect_per_cpu:
                per_cpu = psutil.cpu_percent(interval=0.1, percpu=True)
                raw_data['per_cpu'] = per_cpu
            
            # CPU frequency
            try:
                freq = psutil.cpu_freq()
                if freq:
                    raw_data['cpu_freq'] = {
                        'current': freq.current,
                        'min': freq.min,
                        'max': freq.max
                    }
            except:
                pass
            
            normalized = {
                'cpu_percent': cpu_percent,
                'cpu_user': cpu_times.user,
                'cpu_system': cpu_times.system,
                'cpu_idle': cpu_times.idle,
                'cpu_iowait': getattr(cpu_times, 'iowait', 0),
                'cpu_count': cpu_count_logical
            }
            
            # Determine severity
            severity = 'info'
            if cpu_percent >= self.CPU_CRITICAL_THRESHOLD:
                severity = 'critical'
            elif cpu_percent >= self.CPU_WARNING_THRESHOLD:
                severity = 'warning'
            
            tags = ['metrics', 'cpu']
            if severity != 'info':
                tags.append('high_usage')
            
            return self._create_event(
                event_type='cpu_metrics',
                severity=severity,
                raw_data=raw_data,
                normalized_data=normalized,
                tags=tags
            )
            
        except Exception as e:
            logger.error(f"Error collecting CPU metrics: {e}")
            return None
    
    def _collect_memory_metrics(self) -> Optional[CollectedEvent]:
        """Collect memory metrics"""
        try:
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            raw_data = {
                'virtual': {
                    'total': mem.total,
                    'available': mem.available,
                    'used': mem.used,
                    'free': mem.free,
                    'percent': mem.percent,
                    'cached': getattr(mem, 'cached', 0),
                    'buffers': getattr(mem, 'buffers', 0)
                },
                'swap': {
                    'total': swap.total,
                    'used': swap.used,
                    'free': swap.free,
                    'percent': swap.percent
                }
            }
            
            normalized = {
                'memory_percent': mem.percent,
                'memory_used_gb': mem.used / (1024**3),
                'memory_available_gb': mem.available / (1024**3),
                'memory_total_gb': mem.total / (1024**3),
                'swap_percent': swap.percent,
                'swap_used_gb': swap.used / (1024**3)
            }
            
            # Determine severity
            severity = 'info'
            if mem.percent >= self.MEMORY_CRITICAL_THRESHOLD:
                severity = 'critical'
            elif mem.percent >= self.MEMORY_WARNING_THRESHOLD:
                severity = 'warning'
            
            tags = ['metrics', 'memory']
            if severity != 'info':
                tags.append('high_usage')
            
            return self._create_event(
                event_type='memory_metrics',
                severity=severity,
                raw_data=raw_data,
                normalized_data=normalized,
                tags=tags
            )
            
        except Exception as e:
            logger.error(f"Error collecting memory metrics: {e}")
            return None
    
    def _collect_disk_metrics(self) -> Optional[CollectedEvent]:
        """Collect disk space metrics"""
        try:
            partitions = psutil.disk_partitions()
            
            disk_data = {}
            total_used = 0
            total_total = 0
            highest_percent = 0
            
            for part in partitions:
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disk_data[part.mountpoint] = {
                        'device': part.device,
                        'fstype': part.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    }
                    total_used += usage.used
                    total_total += usage.total
                    highest_percent = max(highest_percent, usage.percent)
                except (PermissionError, OSError):
                    continue
            
            raw_data = {'partitions': disk_data}
            
            normalized = {
                'disk_count': len(disk_data),
                'total_used_gb': total_used / (1024**3),
                'total_capacity_gb': total_total / (1024**3),
                'highest_usage_percent': highest_percent,
                'partitions': list(disk_data.keys())
            }
            
            # Determine severity
            severity = 'info'
            if highest_percent >= self.DISK_CRITICAL_THRESHOLD:
                severity = 'critical'
            elif highest_percent >= self.DISK_WARNING_THRESHOLD:
                severity = 'warning'
            
            tags = ['metrics', 'disk']
            if severity != 'info':
                tags.append('high_usage')
            
            return self._create_event(
                event_type='disk_metrics',
                severity=severity,
                raw_data=raw_data,
                normalized_data=normalized,
                tags=tags
            )
            
        except Exception as e:
            logger.error(f"Error collecting disk metrics: {e}")
            return None
    
    def _collect_disk_io(self) -> Optional[CollectedEvent]:
        """Collect disk I/O metrics"""
        try:
            current_time = time.time()
            io = psutil.disk_io_counters()
            
            if self._last_disk_io and self._last_collect_time:
                time_delta = current_time - self._last_collect_time
                
                read_bytes = io.read_bytes - self._last_disk_io['read_bytes']
                write_bytes = io.write_bytes - self._last_disk_io['write_bytes']
                read_count = io.read_count - self._last_disk_io['read_count']
                write_count = io.write_count - self._last_disk_io['write_count']
                
                raw_data = {
                    'read_bytes': io.read_bytes,
                    'write_bytes': io.write_bytes,
                    'read_count': io.read_count,
                    'write_count': io.write_count,
                    'delta_read_bytes': read_bytes,
                    'delta_write_bytes': write_bytes,
                    'delta_read_count': read_count,
                    'delta_write_count': write_count
                }
                
                normalized = {
                    'read_bytes_per_sec': read_bytes / time_delta if time_delta > 0 else 0,
                    'write_bytes_per_sec': write_bytes / time_delta if time_delta > 0 else 0,
                    'read_ops_per_sec': read_count / time_delta if time_delta > 0 else 0,
                    'write_ops_per_sec': write_count / time_delta if time_delta > 0 else 0,
                    'read_mb_per_sec': (read_bytes / (1024**2)) / time_delta if time_delta > 0 else 0,
                    'write_mb_per_sec': (write_bytes / (1024**2)) / time_delta if time_delta > 0 else 0
                }
                
                # High I/O warning
                severity = 'info'
                total_mb = (read_bytes + write_bytes) / (1024**2)
                if total_mb / time_delta > 100:  # > 100 MB/s
                    severity = 'warning'
                
                self._last_disk_io = {
                    'read_bytes': io.read_bytes,
                    'write_bytes': io.write_bytes,
                    'read_count': io.read_count,
                    'write_count': io.write_count
                }
                self._last_collect_time = current_time
                
                return self._create_event(
                    event_type='disk_io_metrics',
                    severity=severity,
                    raw_data=raw_data,
                    normalized_data=normalized,
                    tags=['metrics', 'disk_io']
                )
            else:
                self._last_disk_io = {
                    'read_bytes': io.read_bytes,
                    'write_bytes': io.write_bytes,
                    'read_count': io.read_count,
                    'write_count': io.write_count
                }
                self._last_collect_time = current_time
            
        except Exception as e:
            logger.error(f"Error collecting disk I/O: {e}")
        
        return None
    
    def _collect_load_average(self) -> Optional[CollectedEvent]:
        """Collect system load average (Unix-like systems)"""
        try:
            if self.os_type in ['linux', 'macos']:
                load1, load5, load15 = psutil.getloadavg()
                cpu_count = psutil.cpu_count()
                
                raw_data = {
                    'load1': load1,
                    'load5': load5,
                    'load15': load15,
                    'cpu_count': cpu_count
                }
                
                normalized = {
                    'load1': load1,
                    'load5': load5,
                    'load15': load15,
                    'load1_per_cpu': load1 / cpu_count if cpu_count else 0,
                    'load5_per_cpu': load5 / cpu_count if cpu_count else 0,
                    'load15_per_cpu': load15 / cpu_count if cpu_count else 0
                }
                
                # High load warning
                severity = 'info'
                if load1 / cpu_count > 2.0:
                    severity = 'critical'
                elif load1 / cpu_count > 1.0:
                    severity = 'warning'
                
                return self._create_event(
                    event_type='load_average',
                    severity=severity,
                    raw_data=raw_data,
                    normalized_data=normalized,
                    tags=['metrics', 'load']
                )
            
        except Exception as e:
            logger.error(f"Error collecting load average: {e}")
        
        return None
    
    def _collect_temperatures(self) -> Optional[CollectedEvent]:
        """Collect temperature sensor data"""
        try:
            temps = psutil.sensors_temperatures()
            
            if temps:
                temp_data = {}
                max_temp = 0
                
                for name, entries in temps.items():
                    temp_data[name] = []
                    for entry in entries:
                        temp_data[name].append({
                            'label': entry.label,
                            'current': entry.current,
                            'high': entry.high,
                            'critical': entry.critical
                        })
                        max_temp = max(max_temp, entry.current)
                
                severity = 'info'
                if max_temp > 90:
                    severity = 'critical'
                elif max_temp > 80:
                    severity = 'warning'
                
                return self._create_event(
                    event_type='temperature_metrics',
                    severity=severity,
                    raw_data={'sensors': temp_data},
                    normalized_data={
                        'max_temperature': max_temp,
                        'sensor_count': len(temps)
                    },
                    tags=['metrics', 'temperature']
                )
                
        except Exception as e:
            logger.debug(f"Temperature sensors not available: {e}")
        
        return None
    
    def _create_health_summary(self, events: List[CollectedEvent]) -> Optional[CollectedEvent]:
        """Create overall system health summary"""
        try:
            health_score = 100
            issues = []
            
            for event in events:
                if event.severity == 'critical':
                    health_score -= 30
                    issues.append(f"Critical: {event.event_type}")
                elif event.severity == 'warning':
                    health_score -= 10
                    issues.append(f"Warning: {event.event_type}")
            
            health_score = max(0, health_score)
            
            # Determine overall severity
            if health_score < 50:
                severity = 'critical'
                status = 'unhealthy'
            elif health_score < 80:
                severity = 'warning'
                status = 'degraded'
            else:
                severity = 'info'
                status = 'healthy'
            
            return self._create_event(
                event_type='system_health',
                severity=severity,
                raw_data={
                    'health_score': health_score,
                    'issues': issues,
                    'metrics_collected': len(events)
                },
                normalized_data={
                    'health_score': health_score,
                    'status': status,
                    'issue_count': len(issues)
                },
                tags=['metrics', 'health']
            )
            
        except Exception as e:
            logger.error(f"Error creating health summary: {e}")
            return None
    
    def get_snapshot(self) -> Dict[str, Any]:
        """Get a quick snapshot of current system metrics"""
        if not PSUTIL_AVAILABLE:
            return {}
        
        return {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': max(
                (psutil.disk_usage(p.mountpoint).percent 
                 for p in psutil.disk_partitions() 
                 if not p.mountpoint.startswith('/snap')),
                default=0
            ),
            'process_count': len(psutil.pids()),
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
        }
