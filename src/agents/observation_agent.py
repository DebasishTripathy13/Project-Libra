"""
Observation Agent for Data Collection and Preprocessing.

Collects security data from multiple sources, preprocesses it,
extracts features, and distributes to other agents.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional
import logging

from .base_agent import BaseAgent, AgentMessage, AgentState, MessagePriority
from ..collectors import LogCollector, ProcessCollector, NetworkCollector, MetricsCollector
from ..ml.feature_extractor import FeatureExtractor, FeatureSet
from ..database.dual_db_manager import DualDatabaseManager


class ObservationAgent(BaseAgent):
    """
    Agent responsible for collecting and preprocessing security data.
    
    Capabilities:
    - Collect logs, process info, network data, system metrics
    - Extract ML features from raw data
    - Store data in tamper-proof database
    - Distribute observations to other agents
    """
    
    # Message types this agent produces
    MSG_NEW_LOG = 'observation.new_log'
    MSG_NEW_PROCESS = 'observation.new_process'
    MSG_NEW_NETWORK = 'observation.new_network'
    MSG_NEW_METRIC = 'observation.new_metric'
    MSG_FEATURE_SET = 'observation.feature_set'
    MSG_BATCH_COMPLETE = 'observation.batch_complete'
    
    def __init__(
        self,
        db_manager: Optional[DualDatabaseManager] = None,
        collection_interval: float = 10.0,
        enable_log_collection: bool = True,
        enable_process_collection: bool = True,
        enable_network_collection: bool = True,
        enable_metrics_collection: bool = True,
        message_handler: Optional[Callable[[AgentMessage], None]] = None,
    ):
        """
        Initialize observation agent.
        
        Args:
            db_manager: Database manager for storing observations
            collection_interval: Seconds between collection cycles
            enable_log_collection: Enable log collection
            enable_process_collection: Enable process collection
            enable_network_collection: Enable network collection
            enable_metrics_collection: Enable system metrics collection
            message_handler: Callback for outbound messages
        """
        super().__init__(
            name='ObservationAgent',
            description='Collects and preprocesses security data',
            message_handler=message_handler,
        )
        
        self.db_manager = db_manager
        self.collection_interval = collection_interval
        
        # Collection flags
        self._enable_log = enable_log_collection
        self._enable_process = enable_process_collection
        self._enable_network = enable_network_collection
        self._enable_metrics = enable_metrics_collection
        
        # Collectors (initialized lazily)
        self._log_collector: Optional[LogCollector] = None
        self._process_collector: Optional[ProcessCollector] = None
        self._network_collector: Optional[NetworkCollector] = None
        self._metrics_collector: Optional[MetricsCollector] = None
        
        # Feature extractor
        self._feature_extractor = FeatureExtractor()
        
        # State
        self._last_collection = datetime.now()
        self._collection_stats = {
            'logs': 0,
            'processes': 0,
            'connections': 0,
            'metrics': 0,
        }
    
    async def _initialize(self) -> None:
        """Initialize collectors."""
        self.logger.info("Initializing collectors...")
        
        try:
            if self._enable_log:
                self._log_collector = LogCollector()
                self.logger.info("Log collector initialized")
            
            if self._enable_process:
                self._process_collector = ProcessCollector()
                self.logger.info("Process collector initialized")
            
            if self._enable_network:
                self._network_collector = NetworkCollector()
                self.logger.info("Network collector initialized")
            
            if self._enable_metrics:
                self._metrics_collector = MetricsCollector()
                self.logger.info("Metrics collector initialized")
            
            # Subscribe to control messages
            self.subscribe('control.collect_now')
            self.subscribe('control.pause_collection')
            self.subscribe('control.resume_collection')
            
        except Exception as e:
            self.logger.error(f"Failed to initialize collectors: {e}")
            raise
    
    async def _cleanup(self) -> None:
        """Clean up resources."""
        self.logger.info("Cleaning up observation agent...")
    
    async def _handle_message(self, message: AgentMessage) -> None:
        """Handle incoming messages."""
        if message.message_type == 'control.collect_now':
            # Immediate collection request
            await self._collect_all()
        
        elif message.message_type == 'control.pause_collection':
            self.logger.info("Collection paused by request")
            await self.pause()
        
        elif message.message_type == 'control.resume_collection':
            self.logger.info("Collection resumed by request")
            await self.resume()
    
    async def _periodic_task(self) -> None:
        """Periodic data collection."""
        elapsed = (datetime.now() - self._last_collection).total_seconds()
        
        if elapsed >= self.collection_interval:
            await self._collect_all()
            self._last_collection = datetime.now()
    
    async def _collect_all(self) -> None:
        """Run all collection tasks."""
        self.logger.debug("Starting collection cycle...")
        
        batch_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        feature_sets: List[FeatureSet] = []
        
        # Collect logs
        if self._log_collector:
            log_features = await self._collect_logs()
            feature_sets.extend(log_features)
        
        # Collect processes
        if self._process_collector:
            process_features = await self._collect_processes()
            feature_sets.extend(process_features)
        
        # Collect network
        if self._network_collector:
            network_features = await self._collect_network()
            feature_sets.extend(network_features)
        
        # Collect metrics
        if self._metrics_collector:
            metric_features = await self._collect_metrics()
            feature_sets.extend(metric_features)
        
        # Broadcast batch completion
        self.broadcast(
            self.MSG_BATCH_COMPLETE,
            {
                'batch_id': batch_id,
                'feature_count': len(feature_sets),
                'stats': self._collection_stats.copy(),
            }
        )
        
        self.logger.debug(f"Collection cycle complete: {len(feature_sets)} features")
    
    async def _collect_logs(self) -> List[FeatureSet]:
        """Collect and process logs."""
        feature_sets = []
        
        try:
            collected = await asyncio.to_thread(self._log_collector.collect)
            
            for log_data in collected.data:
                # Extract features
                features = self._feature_extractor.extract_log_features(
                    message=log_data.get('message', ''),
                    source=log_data.get('source', 'unknown'),
                    timestamp=log_data.get('timestamp'),
                    severity=log_data.get('severity'),
                )
                feature_sets.append(features)
                
                # Store in database
                if self.db_manager:
                    self.db_manager.add_log({
                        'timestamp': features.timestamp.isoformat(),
                        'source': log_data.get('source', 'unknown'),
                        'level': log_data.get('severity', 'info'),
                        'message': log_data.get('message', ''),
                        'hostname': log_data.get('hostname', ''),
                    })
                
                # Send to other agents
                self.broadcast(
                    self.MSG_FEATURE_SET,
                    features,
                    priority=MessagePriority.NORMAL,
                )
            
            self._collection_stats['logs'] += len(collected.data)
            
        except Exception as e:
            self.logger.error(f"Log collection error: {e}")
        
        return feature_sets
    
    async def _collect_processes(self) -> List[FeatureSet]:
        """Collect and process process information."""
        feature_sets = []
        
        try:
            collected = await asyncio.to_thread(self._process_collector.collect)
            
            for proc_data in collected.data:
                # Extract features
                features = self._feature_extractor.extract_process_features(
                    pid=proc_data.get('pid', 0),
                    name=proc_data.get('name', ''),
                    cmdline=proc_data.get('cmdline', ''),
                    user=proc_data.get('user', ''),
                    cpu_percent=proc_data.get('cpu_percent', 0),
                    memory_percent=proc_data.get('memory_percent', 0),
                    connections=proc_data.get('connections', 0),
                    open_files=proc_data.get('open_files', 0),
                    children=proc_data.get('children', 0),
                )
                feature_sets.append(features)
                
                # Send to other agents
                self.broadcast(
                    self.MSG_FEATURE_SET,
                    features,
                    priority=MessagePriority.NORMAL,
                )
            
            self._collection_stats['processes'] += len(collected.data)
            
        except Exception as e:
            self.logger.error(f"Process collection error: {e}")
        
        return feature_sets
    
    async def _collect_network(self) -> List[FeatureSet]:
        """Collect and process network connections."""
        feature_sets = []
        
        try:
            collected = await asyncio.to_thread(self._network_collector.collect)
            
            for conn_data in collected.data:
                # Extract features
                features = self._feature_extractor.extract_network_features(
                    local_addr=conn_data.get('local_addr', ''),
                    local_port=conn_data.get('local_port', 0),
                    remote_addr=conn_data.get('remote_addr', ''),
                    remote_port=conn_data.get('remote_port', 0),
                    protocol=conn_data.get('protocol', 'TCP'),
                    status=conn_data.get('status', ''),
                    bytes_sent=conn_data.get('bytes_sent', 0),
                    bytes_recv=conn_data.get('bytes_recv', 0),
                    process_name=conn_data.get('process', ''),
                )
                feature_sets.append(features)
                
                # Send to other agents
                self.broadcast(
                    self.MSG_FEATURE_SET,
                    features,
                    priority=MessagePriority.NORMAL,
                )
            
            self._collection_stats['connections'] += len(collected.data)
            
        except Exception as e:
            self.logger.error(f"Network collection error: {e}")
        
        return feature_sets
    
    async def _collect_metrics(self) -> List[FeatureSet]:
        """Collect and process system metrics."""
        feature_sets = []
        
        try:
            collected = await asyncio.to_thread(self._metrics_collector.collect)
            
            if collected.data:
                metrics = collected.data[0] if isinstance(collected.data, list) else collected.data
                
                # Extract features
                features = self._feature_extractor.extract_metric_features(
                    cpu_percent=metrics.get('cpu_percent', 0),
                    memory_percent=metrics.get('memory_percent', 0),
                    disk_percent=metrics.get('disk_percent', 0),
                    disk_io_read=metrics.get('disk_io_read', 0),
                    disk_io_write=metrics.get('disk_io_write', 0),
                    net_bytes_sent=metrics.get('net_bytes_sent', 0),
                    net_bytes_recv=metrics.get('net_bytes_recv', 0),
                    process_count=metrics.get('process_count', 0),
                )
                feature_sets.append(features)
                
                # Send to other agents
                self.broadcast(
                    self.MSG_FEATURE_SET,
                    features,
                    priority=MessagePriority.NORMAL,
                )
                
                self._collection_stats['metrics'] += 1
            
        except Exception as e:
            self.logger.error(f"Metrics collection error: {e}")
        
        return feature_sets
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get collection statistics."""
        return {
            **self._collection_stats,
            'last_collection': self._last_collection.isoformat(),
            'collection_interval': self.collection_interval,
        }
