"""
ProjectLibra - Log Source Configuration Loader
Loads and manages log sources from config/log_sources.yaml
"""

import os
import subprocess
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class LogSource:
    """Single log source configuration."""
    name: str
    type: str  # 'file', 'command', 'journalctl'
    enabled: bool = True
    priority: str = 'medium'  # 'critical', 'high', 'medium', 'low'
    description: str = ''
    path: Optional[str] = None  # for type='file'
    command: Optional[str] = None  # for type='command' or 'journalctl'
    include_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)


@dataclass
class LogSourceConfig:
    """Complete log sources configuration."""
    enabled: bool = True
    max_entries_per_source: int = 500
    read_interval: int = 10
    sources: List[LogSource] = field(default_factory=list)
    global_exclude_patterns: List[str] = field(default_factory=list)
    global_include_patterns: List[str] = field(default_factory=list)
    severity_rules: Dict[str, List[str]] = field(default_factory=dict)


class LogSourceLoader:
    """
    Loads log source configuration from YAML and fetches logs.
    """
    
    DEFAULT_CONFIG_PATHS = [
        'config/log_sources.yaml',
        '/etc/projectlibra/log_sources.yaml',
        'log_sources.yaml'
    ]
    
    def __init__(self, config_path: Optional[str] = None, project_root: Optional[str] = None):
        """
        Initialize the log source loader.
        
        Args:
            config_path: Path to log_sources.yaml (optional)
            project_root: Project root directory (optional)
        """
        self.project_root = Path(project_root) if project_root else Path(__file__).parent.parent.parent
        self.config_path = self._find_config(config_path)
        self.config = self._load_config()
        
    def _find_config(self, config_path: Optional[str] = None) -> Optional[Path]:
        """Find the configuration file."""
        if config_path and Path(config_path).exists():
            return Path(config_path)
        
        for path in self.DEFAULT_CONFIG_PATHS:
            full_path = self.project_root / path
            if full_path.exists():
                return full_path
        
        return None
    
    def _load_config(self) -> LogSourceConfig:
        """Load configuration from YAML file."""
        if not self.config_path:
            logger.warning("No log_sources.yaml found, using defaults")
            return self._get_default_config()
        
        try:
            with open(self.config_path, 'r') as f:
                data = yaml.safe_load(f)
            
            return self._parse_config(data)
        except Exception as e:
            logger.error(f"Failed to load log_sources.yaml: {e}")
            return self._get_default_config()
    
    def _parse_config(self, data: Dict[str, Any]) -> LogSourceConfig:
        """Parse YAML data into LogSourceConfig."""
        config = LogSourceConfig(
            enabled=data.get('enabled', True),
            max_entries_per_source=data.get('max_entries_per_source', 500),
            read_interval=data.get('read_interval', 10),
            global_exclude_patterns=data.get('global_filters', {}).get('exclude_patterns', []),
            global_include_patterns=data.get('global_filters', {}).get('always_include_patterns', []),
            severity_rules=data.get('severity_rules', {})
        )
        
        # Parse all source categories
        source_categories = [
            'system_logs', 'auth_logs', 'kernel_logs', 'web_logs',
            'app_logs', 'database_logs', 'security_logs', 'audit_logs', 'custom_logs'
        ]
        
        for category in source_categories:
            if category in data and data[category].get('enabled', False):
                for source_data in data[category].get('sources', []):
                    if source_data.get('enabled', True):
                        source = LogSource(
                            name=source_data.get('name', 'unknown'),
                            type=source_data.get('type', 'file'),
                            enabled=source_data.get('enabled', True),
                            priority=source_data.get('priority', 'medium'),
                            description=source_data.get('description', ''),
                            path=source_data.get('path'),
                            command=source_data.get('command'),
                            include_patterns=source_data.get('include_patterns', []),
                            exclude_patterns=source_data.get('exclude_patterns', [])
                        )
                        config.sources.append(source)
        
        return config
    
    def _get_default_config(self) -> LogSourceConfig:
        """Get default configuration if no config file found."""
        return LogSourceConfig(
            sources=[
                LogSource(
                    name='systemd-journal',
                    type='journalctl',
                    command='journalctl -n 100 --no-pager -o short-iso',
                    priority='high',
                    description='Systemd journal logs'
                ),
                LogSource(
                    name='syslog',
                    type='file',
                    path='/var/log/syslog',
                    priority='high',
                    description='General system messages'
                ),
                LogSource(
                    name='auth',
                    type='file',
                    path='/var/log/auth.log',
                    priority='critical',
                    description='Authentication logs'
                ),
                LogSource(
                    name='dmesg',
                    type='command',
                    command='dmesg -T --level=err,warn,notice 2>/dev/null | tail -100 || dmesg | tail -100',
                    priority='high',
                    description='Kernel ring buffer'
                )
            ]
        )
    
    def get_enabled_sources(self) -> List[LogSource]:
        """Get list of enabled log sources."""
        return [s for s in self.config.sources if s.enabled]
    
    def fetch_logs(self, limit: int = 100) -> Dict[str, str]:
        """
        Fetch logs from all enabled sources.
        
        Args:
            limit: Maximum entries per source
            
        Returns:
            Dictionary mapping source name to log content
        """
        if not self.config.enabled:
            return {}
        
        logs = {}
        entries_per_source = min(limit, self.config.max_entries_per_source)
        
        for source in self.get_enabled_sources():
            try:
                content = self._fetch_source(source, entries_per_source)
                if content:
                    logs[source.name] = content
            except Exception as e:
                logger.warning(f"Failed to fetch {source.name}: {e}")
        
        return logs
    
    def _fetch_source(self, source: LogSource, limit: int) -> Optional[str]:
        """Fetch logs from a single source."""
        if source.type == 'file':
            return self._fetch_file(source.path, limit)
        elif source.type == 'command':
            return self._fetch_command(source.command, limit)
        elif source.type == 'journalctl':
            return self._fetch_journalctl(source.command or f'journalctl -n {limit} --no-pager', limit)
        else:
            logger.warning(f"Unknown source type: {source.type}")
            return None
    
    def _fetch_file(self, path: str, limit: int) -> Optional[str]:
        """Fetch logs from a file."""
        if not path or not os.path.exists(path):
            return None
        
        try:
            # Check if we have read permission
            if not os.access(path, os.R_OK):
                logger.debug(f"No read permission for {path}")
                return None
            
            result = subprocess.run(
                ['tail', '-n', str(limit), path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return result.stdout
            return None
        except Exception as e:
            logger.debug(f"Failed to read {path}: {e}")
            return None
    
    def _fetch_command(self, command: str, limit: int) -> Optional[str]:
        """Fetch logs from a command."""
        if not command:
            return None
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout
            return None
        except Exception as e:
            logger.debug(f"Command failed: {e}")
            return None
    
    def _fetch_journalctl(self, command: str, limit: int) -> Optional[str]:
        """Fetch logs from journalctl."""
        try:
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout
            return None
        except Exception as e:
            logger.debug(f"journalctl failed: {e}")
            return None
    
    def get_source_info(self) -> List[Dict[str, Any]]:
        """Get information about all configured sources."""
        return [
            {
                'name': s.name,
                'type': s.type,
                'enabled': s.enabled,
                'priority': s.priority,
                'description': s.description,
                'path': s.path,
                'available': self._check_source_available(s)
            }
            for s in self.config.sources
        ]
    
    def _check_source_available(self, source: LogSource) -> bool:
        """Check if a source is available on this system."""
        if source.type == 'file':
            return source.path and os.path.exists(source.path)
        elif source.type == 'journalctl':
            return os.path.exists('/bin/journalctl') or os.path.exists('/usr/bin/journalctl')
        else:
            return True  # Commands assumed available
    
    def reload_config(self) -> None:
        """Reload configuration from file."""
        self.config = self._load_config()
        logger.info("Log source configuration reloaded")


# Singleton instance for easy access
_loader_instance: Optional[LogSourceLoader] = None


def get_log_source_loader(config_path: Optional[str] = None) -> LogSourceLoader:
    """Get or create the log source loader singleton."""
    global _loader_instance
    if _loader_instance is None:
        _loader_instance = LogSourceLoader(config_path)
    return _loader_instance


def reload_log_sources() -> None:
    """Reload log source configuration."""
    global _loader_instance
    if _loader_instance:
        _loader_instance.reload_config()
