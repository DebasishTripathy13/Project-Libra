"""
Anomaly Detection Module for Security Analysis.

Provides multiple anomaly detection algorithms for identifying
suspicious behavior patterns in security data.
"""

import math
import random
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
from collections import deque

from .feature_extractor import FeatureSet
from .baseline_learner import BaselineLearner, BehaviorProfile


class AnomalySeverity(Enum):
    """Severity levels for detected anomalies."""
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


@dataclass
class AnomalyResult:
    """Result of anomaly detection analysis."""
    
    is_anomaly: bool
    anomaly_score: float  # 0.0 to 1.0+
    severity: AnomalySeverity
    timestamp: datetime
    source_type: str
    reasons: List[str] = field(default_factory=list)
    feature_contributions: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'is_anomaly': self.is_anomaly,
            'anomaly_score': self.anomaly_score,
            'severity': self.severity.value,
            'timestamp': self.timestamp.isoformat(),
            'source_type': self.source_type,
            'reasons': self.reasons,
            'feature_contributions': self.feature_contributions,
            'metadata': self.metadata,
        }


class AnomalyDetector:
    """
    Multi-algorithm anomaly detector for security events.
    
    Combines multiple detection methods:
    - Statistical (z-score, IQR)
    - Isolation Forest (tree-based)
    - Pattern matching
    - Temporal analysis
    """
    
    def __init__(
        self,
        baseline_learner: Optional[BaselineLearner] = None,
        z_score_threshold: float = 3.0,
        anomaly_threshold: float = 0.6,
        enable_isolation_forest: bool = True,
        isolation_forest_trees: int = 100,
    ):
        """
        Initialize anomaly detector.
        
        Args:
            baseline_learner: Trained baseline learner (or creates new one)
            z_score_threshold: Z-score threshold for statistical detection
            anomaly_threshold: Overall score threshold for anomaly classification
            enable_isolation_forest: Whether to use isolation forest
            isolation_forest_trees: Number of trees for isolation forest
        """
        self.baseline_learner = baseline_learner or BaselineLearner()
        self.z_score_threshold = z_score_threshold
        self.anomaly_threshold = anomaly_threshold
        self.enable_isolation_forest = enable_isolation_forest
        
        # Isolation forest parameters
        self.n_trees = isolation_forest_trees
        self._isolation_forests: Dict[str, List['IsolationTree']] = {}
        self._forest_sample_size = 256
        self._training_data: Dict[str, List[List[float]]] = {}
        
        # Temporal analysis
        self._recent_events: Dict[str, deque] = {}
        self._event_window_size = 100
        
        # Severity thresholds
        self._severity_thresholds = {
            AnomalySeverity.LOW: 0.4,
            AnomalySeverity.MEDIUM: 0.6,
            AnomalySeverity.HIGH: 0.8,
            AnomalySeverity.CRITICAL: 0.95,
        }
    
    def train(self, feature_sets: List[FeatureSet]) -> None:
        """
        Train detector on historical data.
        
        Args:
            feature_sets: List of normal behavior feature sets
        """
        # Train baseline learner
        for fs in feature_sets:
            self.baseline_learner.learn(fs)
        
        # Train isolation forests
        if self.enable_isolation_forest:
            self._train_isolation_forests(feature_sets)
    
    def detect(self, feature_set: FeatureSet) -> AnomalyResult:
        """
        Detect if feature set is anomalous.
        
        Args:
            feature_set: Features to analyze
            
        Returns:
            AnomalyResult with detection details
        """
        scores = []
        reasons = []
        feature_contributions = {}
        
        # 1. Statistical analysis (baseline deviation)
        stat_score, stat_reasons, stat_contributions = self._statistical_analysis(feature_set)
        scores.append(('statistical', stat_score, 0.4))  # (method, score, weight)
        reasons.extend(stat_reasons)
        feature_contributions.update(stat_contributions)
        
        # 2. Isolation forest analysis
        if self.enable_isolation_forest:
            iso_score = self._isolation_forest_score(feature_set)
            if iso_score > 0:
                scores.append(('isolation_forest', iso_score, 0.3))
                if iso_score > 0.5:
                    reasons.append(f"Isolated pattern (score: {iso_score:.2f})")
        
        # 3. Pattern-based analysis
        pattern_score, pattern_reasons = self._pattern_analysis(feature_set)
        scores.append(('pattern', pattern_score, 0.2))
        reasons.extend(pattern_reasons)
        
        # 4. Temporal analysis
        temporal_score, temporal_reasons = self._temporal_analysis(feature_set)
        scores.append(('temporal', temporal_score, 0.1))
        reasons.extend(temporal_reasons)
        
        # Calculate weighted average
        total_weight = sum(s[2] for s in scores)
        weighted_score = sum(s[1] * s[2] for s in scores) / total_weight if total_weight > 0 else 0
        
        # Determine severity
        severity = self._determine_severity(weighted_score)
        
        # Determine if anomaly
        is_anomaly = weighted_score >= self.anomaly_threshold
        
        # Record event for temporal analysis
        self._record_event(feature_set)
        
        return AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_score=weighted_score,
            severity=severity,
            timestamp=feature_set.timestamp,
            source_type=feature_set.source_type,
            reasons=reasons,
            feature_contributions=feature_contributions,
            metadata={
                'detection_methods': {s[0]: s[1] for s in scores},
                'threshold': self.anomaly_threshold,
            },
        )
    
    def detect_batch(self, feature_sets: List[FeatureSet]) -> List[AnomalyResult]:
        """
        Detect anomalies in batch.
        
        Args:
            feature_sets: List of feature sets to analyze
            
        Returns:
            List of AnomalyResults
        """
        return [self.detect(fs) for fs in feature_sets]
    
    def _statistical_analysis(
        self,
        feature_set: FeatureSet,
    ) -> Tuple[float, List[str], Dict[str, float]]:
        """Statistical deviation analysis."""
        profile = self.baseline_learner.get_profile(feature_set.source_type)
        
        if not profile or not profile.is_stable():
            return 0.0, [], {}
        
        deviations = self.baseline_learner.get_feature_deviations(feature_set)
        
        if not deviations:
            return 0.0, [], {}
        
        reasons = []
        contributions = {}
        z_scores = []
        
        for feature_name, (z_score, explanation) in deviations.items():
            z_scores.append(abs(z_score))
            contributions[feature_name] = abs(z_score) / self.z_score_threshold
            
            if abs(z_score) > self.z_score_threshold:
                reasons.append(f"{feature_name}: {explanation}")
        
        # Normalize score (3+ std devs = 1.0)
        avg_z = sum(z_scores) / len(z_scores) if z_scores else 0
        score = min(avg_z / self.z_score_threshold, 1.0)
        
        return score, reasons, contributions
    
    def _isolation_forest_score(self, feature_set: FeatureSet) -> float:
        """Get isolation forest anomaly score."""
        source_type = feature_set.source_type
        
        if source_type not in self._isolation_forests:
            return 0.0
        
        forest = self._isolation_forests[source_type]
        if not forest:
            return 0.0
        
        # Get feature vector
        from .feature_extractor import FeatureExtractor
        feature_names = FeatureExtractor.get_feature_names(source_type)
        vector = feature_set.to_vector(feature_names)
        
        # Calculate average path length
        path_lengths = [tree.path_length(vector) for tree in forest]
        avg_path = sum(path_lengths) / len(path_lengths)
        
        # Calculate anomaly score (shorter paths = more anomalous)
        # Using standard isolation forest scoring
        n = len(self._training_data.get(source_type, []))
        if n <= 1:
            return 0.0
        
        c_n = self._average_path_length(n)
        score = 2 ** (-avg_path / c_n)
        
        return score
    
    def _pattern_analysis(self, feature_set: FeatureSet) -> Tuple[float, List[str]]:
        """Analyze specific suspicious patterns."""
        score = 0.0
        reasons = []
        features = feature_set.features
        
        if feature_set.source_type == 'log':
            # Check for high-severity patterns
            if features.get('max_pattern_score', 0) > 0.8:
                score = max(score, features['max_pattern_score'])
                reasons.append("High-severity pattern detected in log")
            
            # Multiple patterns = more suspicious
            if features.get('pattern_count', 0) >= 3:
                score = max(score, 0.7)
                reasons.append(f"Multiple suspicious patterns ({int(features['pattern_count'])})")
            
            # High entropy (possible obfuscation)
            if features.get('entropy', 0) > 0.9:
                score = max(score, 0.6)
                reasons.append("High entropy suggests obfuscated content")
        
        elif feature_set.source_type == 'process':
            # Suspicious process indicators
            if features.get('is_suspicious_name', 0) > 0:
                score = max(score, 0.8)
                reasons.append("Process name matches known attack tool")
            
            if features.get('has_encoded_data', 0) > 0:
                score = max(score, 0.7)
                reasons.append("Process has encoded/obfuscated arguments")
            
            if features.get('is_root', 0) > 0 and features.get('has_shell_operators', 0) > 0:
                score = max(score, 0.6)
                reasons.append("Root process with shell operators")
        
        elif feature_set.source_type == 'network':
            # Suspicious network patterns
            if features.get('is_high_port', 0) > 0 and features.get('is_remote_public', 0) > 0:
                score = max(score, 0.5)
                reasons.append("Connection to public IP on high port (possible C2)")
            
            if features.get('is_suspicious_process', 0) > 0:
                score = max(score, 0.8)
                reasons.append("Network activity from suspicious process")
            
            # Large data transfer
            if features.get('bytes_sent_normalized', 0) > 0.8:
                score = max(score, 0.5)
                reasons.append("Large outbound data transfer")
        
        elif feature_set.source_type == 'metric':
            # Resource exhaustion patterns
            if features.get('overall_stress', 0) > 0.8:
                score = max(score, 0.6)
                reasons.append("System resource stress detected")
        
        return score, reasons
    
    def _temporal_analysis(self, feature_set: FeatureSet) -> Tuple[float, List[str]]:
        """Analyze temporal patterns."""
        source_type = feature_set.source_type
        reasons = []
        score = 0.0
        
        # Check for unusual timing
        features = feature_set.features
        
        if features.get('is_business_hours', 0) == 0:
            # Activity outside business hours is slightly more suspicious
            score += 0.2
            if features.get('severity_score', 0) > 0.5:
                reasons.append("High-severity event outside business hours")
        
        # Check recent event frequency
        if source_type in self._recent_events:
            recent = self._recent_events[source_type]
            if len(recent) >= 10:
                # Check for burst activity
                time_span = (feature_set.timestamp - recent[0]).total_seconds()
                if time_span > 0:
                    events_per_minute = (len(recent) / time_span) * 60
                    if events_per_minute > 100:  # More than 100 events per minute
                        score = max(score, 0.7)
                        reasons.append(f"High event frequency ({events_per_minute:.0f}/min)")
        
        return min(score, 1.0), reasons
    
    def _record_event(self, feature_set: FeatureSet) -> None:
        """Record event for temporal analysis."""
        source_type = feature_set.source_type
        if source_type not in self._recent_events:
            self._recent_events[source_type] = deque(maxlen=self._event_window_size)
        self._recent_events[source_type].append(feature_set.timestamp)
    
    def _determine_severity(self, score: float) -> AnomalySeverity:
        """Determine severity from score."""
        if score >= self._severity_thresholds[AnomalySeverity.CRITICAL]:
            return AnomalySeverity.CRITICAL
        elif score >= self._severity_thresholds[AnomalySeverity.HIGH]:
            return AnomalySeverity.HIGH
        elif score >= self._severity_thresholds[AnomalySeverity.MEDIUM]:
            return AnomalySeverity.MEDIUM
        else:
            return AnomalySeverity.LOW
    
    def _train_isolation_forests(self, feature_sets: List[FeatureSet]) -> None:
        """Train isolation forests for each source type."""
        from .feature_extractor import FeatureExtractor
        
        # Group by source type
        by_type: Dict[str, List[FeatureSet]] = {}
        for fs in feature_sets:
            if fs.source_type not in by_type:
                by_type[fs.source_type] = []
            by_type[fs.source_type].append(fs)
        
        # Train forest for each type
        for source_type, samples in by_type.items():
            feature_names = FeatureExtractor.get_feature_names(source_type)
            vectors = [fs.to_vector(feature_names) for fs in samples]
            
            self._training_data[source_type] = vectors
            self._isolation_forests[source_type] = self._build_forest(vectors)
    
    def _build_forest(self, data: List[List[float]]) -> List['IsolationTree']:
        """Build isolation forest from data."""
        if len(data) < 2:
            return []
        
        trees = []
        sample_size = min(self._forest_sample_size, len(data))
        max_depth = int(math.ceil(math.log2(sample_size)))
        
        for _ in range(self.n_trees):
            # Random sample
            sample = random.sample(data, sample_size)
            tree = IsolationTree(max_depth=max_depth)
            tree.fit(sample)
            trees.append(tree)
        
        return trees
    
    @staticmethod
    def _average_path_length(n: int) -> float:
        """Calculate average path length for normalization."""
        if n <= 1:
            return 0
        if n == 2:
            return 1
        return 2 * (math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n)


class IsolationTree:
    """Simple isolation tree implementation."""
    
    def __init__(self, max_depth: int = 10):
        self.max_depth = max_depth
        self.root = None
        self.n_features = 0
    
    def fit(self, data: List[List[float]]) -> None:
        """Build tree from data."""
        if not data:
            return
        self.n_features = len(data[0])
        self.root = self._build_tree(data, 0)
    
    def path_length(self, point: List[float]) -> float:
        """Get path length for a point."""
        return self._traverse(point, self.root, 0)
    
    def _build_tree(
        self,
        data: List[List[float]],
        depth: int,
    ) -> Dict[str, Any]:
        """Recursively build tree."""
        if depth >= self.max_depth or len(data) <= 1:
            return {'type': 'leaf', 'size': len(data)}
        
        # Random split
        feature_idx = random.randint(0, self.n_features - 1)
        values = [d[feature_idx] for d in data]
        min_val, max_val = min(values), max(values)
        
        if min_val == max_val:
            return {'type': 'leaf', 'size': len(data)}
        
        split_value = random.uniform(min_val, max_val)
        
        left_data = [d for d in data if d[feature_idx] < split_value]
        right_data = [d for d in data if d[feature_idx] >= split_value]
        
        if not left_data or not right_data:
            return {'type': 'leaf', 'size': len(data)}
        
        return {
            'type': 'split',
            'feature': feature_idx,
            'value': split_value,
            'left': self._build_tree(left_data, depth + 1),
            'right': self._build_tree(right_data, depth + 1),
        }
    
    def _traverse(self, point: List[float], node: Dict, depth: int) -> float:
        """Traverse tree to get path length."""
        if node is None:
            return depth
        
        if node['type'] == 'leaf':
            # Add expected path length for remaining points
            n = node['size']
            if n <= 1:
                return depth
            return depth + AnomalyDetector._average_path_length(n)
        
        feature_idx = node['feature']
        if point[feature_idx] < node['value']:
            return self._traverse(point, node['left'], depth + 1)
        else:
            return self._traverse(point, node['right'], depth + 1)


class EnsembleAnomalyDetector:
    """
    Ensemble anomaly detector combining multiple detection strategies.
    
    Provides more robust detection by combining votes from multiple
    independent detectors.
    """
    
    def __init__(
        self,
        detectors: Optional[List[AnomalyDetector]] = None,
        voting_threshold: float = 0.5,
    ):
        """
        Initialize ensemble detector.
        
        Args:
            detectors: List of anomaly detectors (creates defaults if None)
            voting_threshold: Fraction of detectors that must agree
        """
        self.detectors = detectors or [
            AnomalyDetector(z_score_threshold=2.5, anomaly_threshold=0.5),
            AnomalyDetector(z_score_threshold=3.0, anomaly_threshold=0.6),
            AnomalyDetector(z_score_threshold=3.5, anomaly_threshold=0.7),
        ]
        self.voting_threshold = voting_threshold
    
    def train(self, feature_sets: List[FeatureSet]) -> None:
        """Train all detectors."""
        for detector in self.detectors:
            detector.train(feature_sets)
    
    def detect(self, feature_set: FeatureSet) -> AnomalyResult:
        """
        Detect using ensemble voting.
        
        Returns anomaly if threshold fraction of detectors agree.
        """
        results = [d.detect(feature_set) for d in self.detectors]
        
        # Count votes
        anomaly_votes = sum(1 for r in results if r.is_anomaly)
        vote_fraction = anomaly_votes / len(self.detectors)
        
        # Aggregate scores
        avg_score = sum(r.anomaly_score for r in results) / len(results)
        max_score = max(r.anomaly_score for r in results)
        
        # Combine reasons
        all_reasons = set()
        for r in results:
            all_reasons.update(r.reasons)
        
        # Combine contributions
        all_contributions = {}
        for r in results:
            for feature, contrib in r.feature_contributions.items():
                all_contributions[feature] = max(
                    all_contributions.get(feature, 0),
                    contrib
                )
        
        # Determine final verdict
        is_anomaly = vote_fraction >= self.voting_threshold
        
        # Use max severity if anomaly, otherwise average
        if is_anomaly:
            severity = max(r.severity for r in results)
        else:
            severity = results[0].severity
        
        return AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_score=avg_score,
            severity=severity,
            timestamp=feature_set.timestamp,
            source_type=feature_set.source_type,
            reasons=list(all_reasons),
            feature_contributions=all_contributions,
            metadata={
                'ensemble_votes': anomaly_votes,
                'ensemble_size': len(self.detectors),
                'vote_fraction': vote_fraction,
                'max_score': max_score,
            },
        )
