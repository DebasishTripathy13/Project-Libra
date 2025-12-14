"""
Learning Agent for Continuous Improvement.

Continuously learns from security events to improve
detection accuracy and reduce false positives.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple
from pathlib import Path
import json
import logging

from .base_agent import BaseAgent, AgentMessage, AgentState, MessagePriority
from ..ml.baseline_learner import BaselineLearner, TimeBasedBaseline
from ..ml.anomaly_detector import AnomalyResult
from ..ml.feature_extractor import FeatureSet


@dataclass
class LearningMetrics:
    """Metrics tracking learning performance."""
    
    samples_learned: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    feedback_received: int = 0
    model_updates: int = 0
    last_update: Optional[datetime] = None
    
    @property
    def accuracy(self) -> float:
        """Calculate accuracy."""
        total = self.true_positives + self.true_negatives + self.false_positives + self.false_negatives
        if total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / total
    
    @property
    def precision(self) -> float:
        """Calculate precision."""
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)
    
    @property
    def recall(self) -> float:
        """Calculate recall."""
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)
    
    @property
    def f1_score(self) -> float:
        """Calculate F1 score."""
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'samples_learned': self.samples_learned,
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'true_negatives': self.true_negatives,
            'false_negatives': self.false_negatives,
            'feedback_received': self.feedback_received,
            'model_updates': self.model_updates,
            'accuracy': self.accuracy,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'last_update': self.last_update.isoformat() if self.last_update else None,
        }


@dataclass
class FeedbackRecord:
    """Record of operator feedback on detection."""
    
    timestamp: datetime
    event_id: str
    was_anomaly: bool
    operator_assessment: bool  # True if actually malicious
    confidence: float
    notes: str = ''
    
    @property
    def is_true_positive(self) -> bool:
        return self.was_anomaly and self.operator_assessment
    
    @property
    def is_false_positive(self) -> bool:
        return self.was_anomaly and not self.operator_assessment
    
    @property
    def is_true_negative(self) -> bool:
        return not self.was_anomaly and not self.operator_assessment
    
    @property
    def is_false_negative(self) -> bool:
        return not self.was_anomaly and self.operator_assessment


class LearningAgent(BaseAgent):
    """
    Agent for continuous learning and model improvement.
    
    Capabilities:
    - Online baseline learning from normal behavior
    - Feedback incorporation for supervised learning
    - False positive reduction
    - Adaptive threshold adjustment
    - Model persistence and versioning
    """
    
    # Message types
    MSG_MODEL_UPDATED = 'learning.model_updated'
    MSG_METRICS_REPORT = 'learning.metrics_report'
    MSG_THRESHOLD_ADJUSTED = 'learning.threshold_adjusted'
    
    def __init__(
        self,
        data_dir: Optional[Path] = None,
        learning_rate: float = 0.1,
        min_samples_for_stable: int = 100,
        save_interval: timedelta = timedelta(hours=1),
        enable_time_based: bool = True,
        message_handler: Optional[Callable[[AgentMessage], None]] = None,
    ):
        """
        Initialize learning agent.
        
        Args:
            data_dir: Directory for storing learned models
            learning_rate: Rate for online learning updates
            min_samples_for_stable: Minimum samples for stable baseline
            save_interval: Interval for saving models to disk
            enable_time_based: Use time-based baselines
            message_handler: Callback for outbound messages
        """
        super().__init__(
            name='LearningAgent',
            description='Continuous learning and model improvement',
            message_handler=message_handler,
        )
        
        self.data_dir = Path(data_dir) if data_dir else Path('./data/learning')
        self.learning_rate = learning_rate
        self.min_samples = min_samples_for_stable
        self.save_interval = save_interval
        self.enable_time_based = enable_time_based
        
        # Learning components
        self._baseline_learner: Optional[BaselineLearner] = None
        self._time_baseline: Optional[TimeBasedBaseline] = None
        
        # Metrics
        self.metrics = LearningMetrics()
        
        # Feedback storage
        self._feedback_records: List[FeedbackRecord] = []
        self._max_feedback_records = 10000
        
        # State
        self._last_save = datetime.now()
        self._pending_samples: List[FeatureSet] = []
        self._batch_size = 100
        
        # Threshold adjustments
        self._anomaly_threshold = 0.6
        self._threshold_history: List[Tuple[datetime, float]] = []
    
    async def _initialize(self) -> None:
        """Initialize agent."""
        self.logger.info("Initializing learning agent...")
        
        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize learners
        self._baseline_learner = BaselineLearner(
            data_dir=self.data_dir / 'baselines',
            learning_rate=self.learning_rate,
            min_samples=self.min_samples,
        )
        
        if self.enable_time_based:
            self._time_baseline = TimeBasedBaseline(
                data_dir=self.data_dir / 'time_baselines',
            )
        
        # Load existing models
        self._load_models()
        
        # Subscribe to relevant messages
        self.subscribe('observation.feature_set')
        self.subscribe('anomaly.detected')
        self.subscribe('learning.feedback')
        self.subscribe('learning.reset')
    
    async def _cleanup(self) -> None:
        """Clean up resources."""
        self.logger.info("Cleaning up learning agent...")
        
        # Save models before shutdown
        self._save_models()
    
    async def _handle_message(self, message: AgentMessage) -> None:
        """Handle incoming messages."""
        if message.message_type == 'observation.feature_set':
            await self._handle_feature_set(message.payload)
        
        elif message.message_type == 'anomaly.detected':
            await self._handle_anomaly(message.payload)
        
        elif message.message_type == 'learning.feedback':
            await self._handle_feedback(message.payload)
        
        elif message.message_type == 'learning.reset':
            await self._handle_reset(message.payload)
    
    async def _periodic_task(self) -> None:
        """Periodic learning tasks."""
        # Process pending samples
        if len(self._pending_samples) >= self._batch_size:
            await self._process_batch()
        
        # Save models periodically
        if datetime.now() - self._last_save > self.save_interval:
            self._save_models()
            self._last_save = datetime.now()
        
        # Adjust thresholds based on feedback
        if self.metrics.feedback_received > 0 and self.metrics.feedback_received % 50 == 0:
            await self._adjust_thresholds()
    
    async def _handle_feature_set(self, feature_set: FeatureSet) -> None:
        """Process feature set for learning."""
        self._pending_samples.append(feature_set)
        
        # Online learning for baseline
        self._baseline_learner.learn(feature_set)
        
        if self._time_baseline:
            self._time_baseline.learn(feature_set)
        
        self.metrics.samples_learned += 1
    
    async def _handle_anomaly(self, anomaly: AnomalyResult) -> None:
        """Track anomaly detection for metrics."""
        # Will be updated when feedback is received
        pass
    
    async def _handle_feedback(self, feedback: Dict[str, Any]) -> None:
        """Process operator feedback on detection."""
        record = FeedbackRecord(
            timestamp=datetime.now(),
            event_id=feedback.get('event_id', ''),
            was_anomaly=feedback.get('was_anomaly', True),
            operator_assessment=feedback.get('is_malicious', False),
            confidence=feedback.get('confidence', 1.0),
            notes=feedback.get('notes', ''),
        )
        
        # Update metrics
        if record.is_true_positive:
            self.metrics.true_positives += 1
        elif record.is_false_positive:
            self.metrics.false_positives += 1
        elif record.is_true_negative:
            self.metrics.true_negatives += 1
        elif record.is_false_negative:
            self.metrics.false_negatives += 1
        
        self.metrics.feedback_received += 1
        
        # Store feedback
        self._feedback_records.append(record)
        if len(self._feedback_records) > self._max_feedback_records:
            self._feedback_records.pop(0)
        
        self.logger.info(
            f"Feedback received: {'TP' if record.is_true_positive else 'FP' if record.is_false_positive else 'TN' if record.is_true_negative else 'FN'}"
        )
    
    async def _handle_reset(self, params: Dict[str, Any]) -> None:
        """Reset learning models."""
        reset_type = params.get('type', 'all')
        
        if reset_type in ('all', 'baseline'):
            self._baseline_learner = BaselineLearner(
                data_dir=self.data_dir / 'baselines',
                learning_rate=self.learning_rate,
                min_samples=self.min_samples,
            )
        
        if reset_type in ('all', 'time_baseline') and self._time_baseline:
            self._time_baseline = TimeBasedBaseline(
                data_dir=self.data_dir / 'time_baselines',
            )
        
        if reset_type in ('all', 'metrics'):
            self.metrics = LearningMetrics()
        
        self.logger.info(f"Learning reset: {reset_type}")
    
    async def _process_batch(self) -> None:
        """Process batch of pending samples."""
        if not self._pending_samples:
            return
        
        # Batch learning (already done online, this is for any batch-specific processing)
        batch_size = len(self._pending_samples)
        self._pending_samples.clear()
        
        self.metrics.model_updates += 1
        self.metrics.last_update = datetime.now()
        
        self.logger.debug(f"Processed batch of {batch_size} samples")
    
    async def _adjust_thresholds(self) -> None:
        """Adjust detection thresholds based on feedback."""
        if self.metrics.feedback_received < 20:
            return  # Not enough feedback
        
        # Calculate optimal threshold based on feedback
        # Goal: Balance precision and recall
        
        current_precision = self.metrics.precision
        current_recall = self.metrics.recall
        
        old_threshold = self._anomaly_threshold
        
        if current_precision < 0.7 and self.metrics.false_positives > 10:
            # Too many false positives, raise threshold
            self._anomaly_threshold = min(self._anomaly_threshold + 0.05, 0.95)
            self.logger.info(f"Raised anomaly threshold to {self._anomaly_threshold:.2f} (precision was {current_precision:.2f})")
        
        elif current_recall < 0.7 and self.metrics.false_negatives > 10:
            # Missing too many threats, lower threshold
            self._anomaly_threshold = max(self._anomaly_threshold - 0.05, 0.3)
            self.logger.info(f"Lowered anomaly threshold to {self._anomaly_threshold:.2f} (recall was {current_recall:.2f})")
        
        if self._anomaly_threshold != old_threshold:
            self._threshold_history.append((datetime.now(), self._anomaly_threshold))
            
            self.broadcast(
                self.MSG_THRESHOLD_ADJUSTED,
                {
                    'old_threshold': old_threshold,
                    'new_threshold': self._anomaly_threshold,
                    'reason': 'feedback_optimization',
                    'precision': current_precision,
                    'recall': current_recall,
                },
                priority=MessagePriority.NORMAL,
            )
    
    def _save_models(self) -> None:
        """Save learned models to disk."""
        try:
            # Save baseline profiles
            self._baseline_learner.save_profiles()
            
            if self._time_baseline:
                self._time_baseline.save_all()
            
            # Save metrics
            metrics_path = self.data_dir / 'metrics.json'
            with open(metrics_path, 'w') as f:
                json.dump(self.metrics.to_dict(), f, indent=2)
            
            # Save threshold history
            threshold_path = self.data_dir / 'thresholds.json'
            with open(threshold_path, 'w') as f:
                json.dump([
                    {'timestamp': ts.isoformat(), 'threshold': th}
                    for ts, th in self._threshold_history
                ], f, indent=2)
            
            self.logger.info("Models saved to disk")
            
        except Exception as e:
            self.logger.error(f"Failed to save models: {e}")
    
    def _load_models(self) -> None:
        """Load models from disk."""
        try:
            # Load metrics
            metrics_path = self.data_dir / 'metrics.json'
            if metrics_path.exists():
                with open(metrics_path, 'r') as f:
                    data = json.load(f)
                    self.metrics.samples_learned = data.get('samples_learned', 0)
                    self.metrics.true_positives = data.get('true_positives', 0)
                    self.metrics.false_positives = data.get('false_positives', 0)
                    self.metrics.true_negatives = data.get('true_negatives', 0)
                    self.metrics.false_negatives = data.get('false_negatives', 0)
                    self.metrics.feedback_received = data.get('feedback_received', 0)
                    self.metrics.model_updates = data.get('model_updates', 0)
            
            # Load threshold history
            threshold_path = self.data_dir / 'thresholds.json'
            if threshold_path.exists():
                with open(threshold_path, 'r') as f:
                    data = json.load(f)
                    self._threshold_history = [
                        (datetime.fromisoformat(item['timestamp']), item['threshold'])
                        for item in data
                    ]
                    if self._threshold_history:
                        self._anomaly_threshold = self._threshold_history[-1][1]
            
            self.logger.info("Models loaded from disk")
            
        except Exception as e:
            self.logger.warning(f"Could not load models: {e}")
    
    def get_baseline_profile(self, source_type: str):
        """Get baseline profile for a source type."""
        return self._baseline_learner.get_profile(source_type)
    
    def get_deviation_score(self, feature_set: FeatureSet) -> float:
        """Get deviation score for a feature set."""
        if self._time_baseline:
            return self._time_baseline.get_deviation_score(feature_set)
        return self._baseline_learner.get_deviation_score(feature_set)
    
    def get_current_threshold(self) -> float:
        """Get current anomaly threshold."""
        return self._anomaly_threshold
    
    def get_learning_metrics(self) -> Dict[str, Any]:
        """Get learning metrics."""
        return self.metrics.to_dict()
    
    def get_feedback_summary(self) -> Dict[str, Any]:
        """Get summary of recent feedback."""
        recent = self._feedback_records[-100:] if self._feedback_records else []
        
        return {
            'total_feedback': len(self._feedback_records),
            'recent_count': len(recent),
            'recent_true_positives': sum(1 for r in recent if r.is_true_positive),
            'recent_false_positives': sum(1 for r in recent if r.is_false_positive),
            'recent_true_negatives': sum(1 for r in recent if r.is_true_negative),
            'recent_false_negatives': sum(1 for r in recent if r.is_false_negative),
        }
