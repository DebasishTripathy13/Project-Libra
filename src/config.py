"""
Configuration Management for ProjectLibra.

Provides YAML-based configuration with environment variable
overrides and validation.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import yaml
import logging


@dataclass
class DatabaseConfig:
    """Database configuration."""
    
    primary_path: str = './data/primary.db'
    backup_path: str = './data/backup.db'
    enable_integrity_checks: bool = True
    check_interval_seconds: int = 60
    

@dataclass
class CollectorConfig:
    """Data collector configuration."""
    
    enabled: bool = True
    interval_seconds: float = 10.0
    
    # Log collector
    log_sources: List[str] = field(default_factory=lambda: ['/var/log/syslog', '/var/log/auth.log'])
    log_max_lines: int = 1000
    
    # Process collector
    process_include_children: bool = True
    process_min_cpu: float = 0.0
    process_min_memory: float = 0.0
    
    # Network collector
    network_include_listening: bool = True
    network_include_established: bool = True
    
    # Metrics collector
    metrics_include_disk: bool = True
    metrics_include_network: bool = True


@dataclass
class LLMConfig:
    """LLM configuration."""
    
    enabled: bool = True
    provider: str = 'ollama'  # ollama, openai, groq, gemini
    model: str = 'llama2'
    api_key: Optional[str] = None
    api_base: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 1000
    timeout_seconds: int = 30


@dataclass 
class MLConfig:
    """Machine learning configuration."""
    
    learning_rate: float = 0.1
    min_samples_for_stable: int = 100
    anomaly_threshold: float = 0.6
    z_score_threshold: float = 3.0
    enable_isolation_forest: bool = True
    isolation_forest_trees: int = 100
    enable_time_based_baseline: bool = True


@dataclass
class AgentConfig:
    """Agent configuration."""
    
    # Observation agent
    collection_interval: float = 10.0
    enable_log_collection: bool = True
    enable_process_collection: bool = True
    enable_network_collection: bool = True
    enable_metrics_collection: bool = True
    
    # Correlation agent
    correlation_window_minutes: int = 5
    min_correlation_score: float = 0.5
    
    # Threat agent
    threat_analysis_threshold: float = 0.5
    enable_llm_analysis: bool = True
    
    # Maintenance agent
    auto_remediate: bool = False
    dry_run: bool = True
    require_approval_threshold: float = 0.8
    allowed_actions: List[str] = field(default_factory=lambda: ['log_event', 'alert_admin'])
    
    # Learning agent
    save_interval_hours: float = 1.0


@dataclass
class APIConfig:
    """API server configuration."""
    
    enabled: bool = True
    host: str = '0.0.0.0'
    port: int = 8000
    debug: bool = False
    cors_origins: List[str] = field(default_factory=lambda: ['*'])
    api_key: Optional[str] = None
    rate_limit_per_minute: int = 100


@dataclass
class LoggingConfig:
    """Logging configuration."""
    
    level: str = 'INFO'
    format: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    file_path: Optional[str] = './logs/projectlibra.log'
    max_size_mb: int = 100
    backup_count: int = 5
    console_output: bool = True


@dataclass
class ProjectLibraConfig:
    """Main configuration class."""
    
    # Sub-configs
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    collectors: CollectorConfig = field(default_factory=CollectorConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    agents: AgentConfig = field(default_factory=AgentConfig)
    api: APIConfig = field(default_factory=APIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    
    # Global settings
    data_dir: str = './data'
    environment: str = 'development'  # development, staging, production
    
    @classmethod
    def load(cls, config_path: Optional[str] = None) -> 'ProjectLibraConfig':
        """
        Load configuration from file and environment.
        
        Args:
            config_path: Path to YAML config file
            
        Returns:
            ProjectLibraConfig instance
        """
        config = cls()
        
        # Try default paths if not specified
        if not config_path:
            default_paths = [
                './config.yaml',
                './config.yml', 
                './config/config.yaml',
                '/etc/projectlibra/config.yaml',
            ]
            for path in default_paths:
                if Path(path).exists():
                    config_path = path
                    break
        
        # Load from file if exists
        if config_path and Path(config_path).exists():
            config._load_from_file(config_path)
        
        # Override from environment variables
        config._load_from_env()
        
        return config
    
    def _load_from_file(self, path: str) -> None:
        """Load configuration from YAML file."""
        with open(path, 'r') as f:
            data = yaml.safe_load(f) or {}
        
        self._apply_dict(data)
    
    def _load_from_env(self) -> None:
        """Load configuration from environment variables."""
        env_mappings = {
            # Database
            'LIBRA_DB_PRIMARY_PATH': ('database', 'primary_path'),
            'LIBRA_DB_BACKUP_PATH': ('database', 'backup_path'),
            'LIBRA_DB_INTEGRITY_CHECK': ('database', 'enable_integrity_checks', bool),
            
            # LLM
            'LIBRA_LLM_PROVIDER': ('llm', 'provider'),
            'LIBRA_LLM_MODEL': ('llm', 'model'),
            'LIBRA_LLM_API_KEY': ('llm', 'api_key'),
            'OPENAI_API_KEY': ('llm', 'api_key'),
            'GROQ_API_KEY': ('llm', 'api_key'),
            'GOOGLE_API_KEY': ('llm', 'api_key'),
            
            # API
            'LIBRA_API_HOST': ('api', 'host'),
            'LIBRA_API_PORT': ('api', 'port', int),
            'LIBRA_API_KEY': ('api', 'api_key'),
            'LIBRA_API_DEBUG': ('api', 'debug', bool),
            
            # Agents
            'LIBRA_AUTO_REMEDIATE': ('agents', 'auto_remediate', bool),
            'LIBRA_DRY_RUN': ('agents', 'dry_run', bool),
            
            # Global
            'LIBRA_DATA_DIR': ('data_dir',),
            'LIBRA_ENV': ('environment',),
            'LIBRA_LOG_LEVEL': ('logging', 'level'),
        }
        
        for env_var, mapping in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                self._set_nested(mapping, value)
    
    def _apply_dict(self, data: Dict[str, Any]) -> None:
        """Apply dictionary to configuration."""
        if 'database' in data:
            for k, v in data['database'].items():
                if hasattr(self.database, k):
                    setattr(self.database, k, v)
        
        if 'collectors' in data:
            for k, v in data['collectors'].items():
                if hasattr(self.collectors, k):
                    setattr(self.collectors, k, v)
        
        if 'llm' in data:
            for k, v in data['llm'].items():
                if hasattr(self.llm, k):
                    setattr(self.llm, k, v)
        
        if 'ml' in data:
            for k, v in data['ml'].items():
                if hasattr(self.ml, k):
                    setattr(self.ml, k, v)
        
        if 'agents' in data:
            for k, v in data['agents'].items():
                if hasattr(self.agents, k):
                    setattr(self.agents, k, v)
        
        if 'api' in data:
            for k, v in data['api'].items():
                if hasattr(self.api, k):
                    setattr(self.api, k, v)
        
        if 'logging' in data:
            for k, v in data['logging'].items():
                if hasattr(self.logging, k):
                    setattr(self.logging, k, v)
        
        if 'data_dir' in data:
            self.data_dir = data['data_dir']
        
        if 'environment' in data:
            self.environment = data['environment']
    
    def _set_nested(self, mapping: tuple, value: str) -> None:
        """Set nested configuration value."""
        if len(mapping) == 1:
            setattr(self, mapping[0], value)
        elif len(mapping) == 2:
            section, key = mapping
            section_obj = getattr(self, section)
            setattr(section_obj, key, value)
        elif len(mapping) == 3:
            section, key, type_fn = mapping
            section_obj = getattr(self, section)
            if type_fn == bool:
                value = value.lower() in ('true', '1', 'yes')
            elif type_fn == int:
                value = int(value)
            elif type_fn == float:
                value = float(value)
            setattr(section_obj, key, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'database': {
                'primary_path': self.database.primary_path,
                'backup_path': self.database.backup_path,
                'enable_integrity_checks': self.database.enable_integrity_checks,
                'check_interval_seconds': self.database.check_interval_seconds,
            },
            'collectors': {
                'enabled': self.collectors.enabled,
                'interval_seconds': self.collectors.interval_seconds,
                'log_sources': self.collectors.log_sources,
                'log_max_lines': self.collectors.log_max_lines,
            },
            'llm': {
                'enabled': self.llm.enabled,
                'provider': self.llm.provider,
                'model': self.llm.model,
                'temperature': self.llm.temperature,
                'max_tokens': self.llm.max_tokens,
            },
            'ml': {
                'learning_rate': self.ml.learning_rate,
                'min_samples_for_stable': self.ml.min_samples_for_stable,
                'anomaly_threshold': self.ml.anomaly_threshold,
                'enable_isolation_forest': self.ml.enable_isolation_forest,
            },
            'agents': {
                'collection_interval': self.agents.collection_interval,
                'auto_remediate': self.agents.auto_remediate,
                'dry_run': self.agents.dry_run,
            },
            'api': {
                'enabled': self.api.enabled,
                'host': self.api.host,
                'port': self.api.port,
            },
            'logging': {
                'level': self.logging.level,
                'file_path': self.logging.file_path,
            },
            'data_dir': self.data_dir,
            'environment': self.environment,
        }
    
    def save(self, path: str) -> None:
        """Save configuration to YAML file."""
        with open(path, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False)
    
    def validate(self) -> List[str]:
        """
        Validate configuration.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Check data directory
        data_dir = Path(self.data_dir)
        if not data_dir.exists():
            try:
                data_dir.mkdir(parents=True)
            except Exception as e:
                errors.append(f"Cannot create data directory: {e}")
        
        # Check LLM configuration
        if self.llm.enabled:
            if self.llm.provider in ('openai', 'groq', 'gemini') and not self.llm.api_key:
                errors.append(f"API key required for {self.llm.provider} LLM provider")
        
        # Check agent configuration
        if self.agents.auto_remediate and not self.agents.dry_run:
            if self.environment != 'production':
                errors.append("Auto-remediation without dry_run should only be enabled in production")
        
        # Check API configuration
        if self.api.enabled:
            if self.api.port < 1 or self.api.port > 65535:
                errors.append(f"Invalid API port: {self.api.port}")
        
        return errors


def get_default_config() -> ProjectLibraConfig:
    """Get default configuration."""
    return ProjectLibraConfig()


def generate_sample_config(path: str = './config.yaml.sample') -> None:
    """Generate a sample configuration file."""
    config = get_default_config()
    
    sample_content = """# ProjectLibra Configuration
# Copy this file to config.yaml and customize

# Database settings for tamper-proof storage
database:
  primary_path: './data/primary.db'
  backup_path: './data/backup.db'
  enable_integrity_checks: true
  check_interval_seconds: 60

# Data collector settings
collectors:
  enabled: true
  interval_seconds: 10.0
  log_sources:
    - '/var/log/syslog'
    - '/var/log/auth.log'
  log_max_lines: 1000

# LLM settings for intelligent analysis
llm:
  enabled: true
  provider: 'ollama'  # Options: ollama, openai, groq, gemini
  model: 'llama2'
  # api_key: 'your-api-key'  # Required for cloud providers
  temperature: 0.7
  max_tokens: 1000

# Machine learning settings
ml:
  learning_rate: 0.1
  min_samples_for_stable: 100
  anomaly_threshold: 0.6
  z_score_threshold: 3.0
  enable_isolation_forest: true

# Agent settings
agents:
  collection_interval: 10.0
  enable_log_collection: true
  enable_process_collection: true
  enable_network_collection: true
  enable_metrics_collection: true
  
  # WARNING: Enable auto-remediation with caution!
  auto_remediate: false
  dry_run: true
  require_approval_threshold: 0.8
  allowed_actions:
    - 'log_event'
    - 'alert_admin'

# API server settings
api:
  enabled: true
  host: '0.0.0.0'
  port: 8000
  debug: false
  # api_key: 'your-secure-api-key'  # Uncomment to enable API authentication

# Logging settings
logging:
  level: 'INFO'
  file_path: './logs/projectlibra.log'
  max_size_mb: 100
  backup_count: 5
  console_output: true

# Global settings
data_dir: './data'
environment: 'development'  # Options: development, staging, production
"""
    
    with open(path, 'w') as f:
        f.write(sample_content)
    
    print(f"Sample configuration written to {path}")


def load_config(config_path: str = None) -> ProjectLibraConfig:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to config file (default: ./config.yaml)
        
    Returns:
        ProjectLibraConfig instance
    """
    import os
    
    if config_path is None:
        # Try common locations
        for path in ['./config.yaml', './config.yml', './projectlibra.yaml']:
            if os.path.exists(path):
                config_path = path
                break
    
    if config_path and os.path.exists(config_path):
        try:
            import yaml
            with open(config_path, 'r') as f:
                data = yaml.safe_load(f)
            return ProjectLibraConfig.from_dict(data)
        except Exception as e:
            print(f"Warning: Could not load config from {config_path}: {e}")
            print("Using default configuration")
    
    return get_default_config()
