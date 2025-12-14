"""
ProjectLibra - Main Application Entry Point.

Agentic AI-Driven Unified Host Security, Behavior Analysis,
and Self-Maintenance Platform.
"""

import asyncio
import signal
import sys
import logging
from pathlib import Path
from typing import Optional
import argparse

from .config import ProjectLibraConfig, generate_sample_config
from .database.dual_db_manager import DualDatabaseManager
from .services.integrity_monitor import IntegrityMonitorService
from .agents.orchestrator import AgentOrchestrator
from .llm import LLMFactory, LLMConfig as LLMClientConfig


class ProjectLibra:
    """
    Main application class for ProjectLibra.
    
    Coordinates all components:
    - Dual database with tamper detection
    - Integrity monitoring
    - AI agent orchestration
    - API server (optional)
    """
    
    def __init__(self, config: Optional[ProjectLibraConfig] = None):
        """
        Initialize ProjectLibra.
        
        Args:
            config: Application configuration
        """
        self.config = config or ProjectLibraConfig.load()
        self.logger = self._setup_logging()
        
        # Components
        self.db_manager: Optional[DualDatabaseManager] = None
        self.integrity_monitor: Optional[IntegrityMonitorService] = None
        self.orchestrator: Optional[AgentOrchestrator] = None
        
        # State
        self._running = False
        self._shutdown_event = asyncio.Event()
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration."""
        log_config = self.config.logging
        
        # Create logger
        logger = logging.getLogger('projectlibra')
        logger.setLevel(getattr(logging, log_config.level.upper(), logging.INFO))
        
        # Create formatter
        formatter = logging.Formatter(log_config.format)
        
        # Console handler
        if log_config.console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        
        # File handler
        if log_config.file_path:
            log_dir = Path(log_config.file_path).parent
            log_dir.mkdir(parents=True, exist_ok=True)
            
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                log_config.file_path,
                maxBytes=log_config.max_size_mb * 1024 * 1024,
                backupCount=log_config.backup_count,
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    async def initialize(self) -> None:
        """Initialize all components."""
        self.logger.info("Initializing ProjectLibra...")
        
        # Validate configuration
        errors = self.config.validate()
        if errors:
            for error in errors:
                self.logger.error(f"Configuration error: {error}")
            raise ValueError("Invalid configuration")
        
        # Create data directory
        data_dir = Path(self.config.data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self.logger.info("Initializing tamper-proof database...")
        self.db_manager = DualDatabaseManager(
            primary_db_path=self.config.database.primary_path,
            backup_db_path=self.config.database.backup_path,
        )
        
        # Initialize integrity monitor
        if self.config.database.enable_integrity_checks:
            self.logger.info("Initializing integrity monitor...")
            self.integrity_monitor = IntegrityMonitorService(
                db_manager=self.db_manager,
                check_interval=self.config.database.check_interval_seconds,
            )
        
        # Initialize LLM client if enabled
        llm_client = None
        if self.config.llm.enabled:
            try:
                llm_config = LLMClientConfig(
                    provider=self.config.llm.provider,
                    model=self.config.llm.model,
                    api_key=self.config.llm.api_key,
                    api_base=self.config.llm.api_base,
                    temperature=self.config.llm.temperature,
                    max_tokens=self.config.llm.max_tokens,
                )
                llm_client = LLMFactory.create(llm_config)
                self.logger.info(f"LLM client initialized: {self.config.llm.provider}")
            except Exception as e:
                self.logger.warning(f"Failed to initialize LLM: {e}")
        
        # Initialize agent orchestrator
        self.logger.info("Initializing agent orchestrator...")
        self.orchestrator = AgentOrchestrator(
            data_dir=data_dir,
            db_manager=self.db_manager,
            llm_client=llm_client,
            enable_auto_remediate=self.config.agents.auto_remediate,
        )
        await self.orchestrator.initialize()
        
        self.logger.info("ProjectLibra initialized successfully")
    
    async def start(self) -> None:
        """Start all services."""
        if self._running:
            return
        
        self.logger.info("Starting ProjectLibra...")
        
        # Start integrity monitor
        if self.integrity_monitor:
            await self.integrity_monitor.start()
        
        # Start agent orchestrator
        await self.orchestrator.start()
        
        self._running = True
        self.logger.info("ProjectLibra started successfully")
        
        # Print status
        self._print_status()
    
    async def stop(self) -> None:
        """Stop all services."""
        if not self._running:
            return
        
        self.logger.info("Stopping ProjectLibra...")
        
        # Stop orchestrator
        if self.orchestrator:
            await self.orchestrator.stop()
        
        # Stop integrity monitor
        if self.integrity_monitor:
            await self.integrity_monitor.stop()
        
        # Close database
        if self.db_manager:
            self.db_manager.close()
        
        self._running = False
        self.logger.info("ProjectLibra stopped")
    
    async def run(self) -> None:
        """Run the application until shutdown."""
        await self.initialize()
        await self.start()
        
        # Set up signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(
                sig,
                lambda: asyncio.create_task(self._handle_shutdown())
            )
        
        # Wait for shutdown
        await self._shutdown_event.wait()
        
        await self.stop()
    
    async def _handle_shutdown(self) -> None:
        """Handle shutdown signal."""
        self.logger.info("Shutdown signal received")
        self._shutdown_event.set()
    
    def _print_status(self) -> None:
        """Print startup status."""
        print("\n" + "=" * 60)
        print("  ProjectLibra - Security Intelligence Platform")
        print("=" * 60)
        print(f"  Environment: {self.config.environment}")
        print(f"  Data Directory: {self.config.data_dir}")
        print(f"  Database: Tamper-proof dual database active")
        print(f"  Integrity Monitor: {'Active' if self.integrity_monitor else 'Disabled'}")
        print(f"  LLM: {self.config.llm.provider if self.config.llm.enabled else 'Disabled'}")
        print(f"  Auto-Remediate: {'Enabled' if self.config.agents.auto_remediate else 'Disabled'}")
        print(f"  API Server: Port {self.config.api.port if self.config.api.enabled else 'Disabled'}")
        print("=" * 60)
        print("  Press Ctrl+C to stop")
        print("=" * 60 + "\n")
    
    def get_status(self) -> dict:
        """Get application status."""
        status = {
            'running': self._running,
            'config': self.config.to_dict(),
        }
        
        if self.orchestrator:
            status['orchestrator'] = self.orchestrator.get_status()
            status['health'] = self.orchestrator.get_health()
        
        if self.db_manager:
            integrity = self.db_manager.verify_integrity()
            status['database'] = {
                'verified_records': integrity.get('verified', 0),
                'missing_records': integrity.get('missing', 0),
                'tampered_records': integrity.get('tampered', 0),
                'healthy': integrity.get('missing', 0) == 0 and integrity.get('tampered', 0) == 0,
            }
        
        return status


def create_app(config_path: Optional[str] = None) -> ProjectLibra:
    """
    Create and configure the application.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configured ProjectLibra instance
    """
    config = ProjectLibraConfig.load(config_path)
    return ProjectLibra(config)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='ProjectLibra - Agentic AI Security Platform'
    )
    parser.add_argument(
        '-c', '--config',
        help='Path to configuration file',
        default=None,
    )
    parser.add_argument(
        '--generate-config',
        help='Generate sample configuration file',
        action='store_true',
    )
    parser.add_argument(
        '--check-config',
        help='Validate configuration and exit',
        action='store_true',
    )
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='ProjectLibra 1.0.0',
    )
    
    args = parser.parse_args()
    
    # Generate sample config
    if args.generate_config:
        generate_sample_config()
        return
    
    # Load and validate config
    config = ProjectLibraConfig.load(args.config)
    
    if args.check_config:
        errors = config.validate()
        if errors:
            print("Configuration errors:")
            for error in errors:
                print(f"  - {error}")
            sys.exit(1)
        else:
            print("Configuration is valid")
            sys.exit(0)
    
    # Create and run application
    app = ProjectLibra(config)
    
    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
