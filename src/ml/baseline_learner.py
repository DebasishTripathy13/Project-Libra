"""
Baseline Learner Module for Behavioral Analysis.

Learns normal system behavior and creates behavioral profiles
for detecting deviations that may indicate security threats.
"""

import json
import pickle
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import math
from collections import defaultdict
import statistics

from .feature_extractor import FeatureExtractor, FeatureSet


@dataclass
class BehaviorProfile:
    """
    Statistical profile of normal behavior.
    
    Maintains running statistics for each feature to detect anomalies.
    """
    
    source_type: str
    feature_stats: Dict[str, Dict[str, float]] = field(default_factory=dict)
    sample_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    min_samples_for_stable: int = 100
    
    def is_stable(self) -> bool:
        """Check if profile has enough samples to be reliable."""
        return self.sample_count >= self.min_samples_for_stable
    
    def get_feature_bounds(self, feature_name: str, std_multiplier: float = 2.0) -> Tuple[float, float]:
        """
        Get expected bounds for a feature.
        
        Args:
            feature_name: Name of the feature
            std_multiplier: Number of standard deviations for bounds
            
        Returns:
            (lower_bound, upper_bound) tuple
        """
        if feature_name not in self.feature_stats:
            return (0.0, 1.0)
        
        stats = self.feature_stats[feature_name]
        mean = stats.get('mean', 0.5)
        std = stats.get('std', 0.25)
        
        lower = max(0.0, mean - std_multiplier * std)
        upper = min(1.0, mean + std_multiplier * std)
        
        return (lower, upper)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary for serialization."""
        return {
            'source_type': self.source_type,
            'feature_stats': self.feature_stats,
            'sample_count': self.sample_count,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BehaviorProfile':
        """Create profile from dictionary."""
        return cls(
            source_type=data['source_type'],
            feature_stats=data['feature_stats'],
            sample_count=data['sample_count'],
            created_at=datetime.fromisoformat(data['created_at']),
            updated_at=datetime.fromisoformat(data['updated_at']),
        )


class BaselineLearner:
    """
    Learns normal behavioral baselines from security data.
    
    Uses online learning to maintain running statistics without
    storing all historical data. Supports multiple source types
    with separate profiles.
    """
    
    def __init__(
        self,
        data_dir: Optional[Path] = None,
        learning_rate: float = 0.1,
        min_samples: int = 100,
    ):
        """
        Initialize baseline learner.
        
        Args:
            data_dir: Directory to store learned profiles
            learning_rate: Rate for exponential moving average updates
            min_samples: Minimum samples before profile is considered stable
        """
        self.data_dir = Path(data_dir) if data_dir else Path('./data/baselines')
        self.learning_rate = learning_rate
        self.min_samples = min_samples
        
        self.profiles: Dict[str, BehaviorProfile] = {}
        self._feature_buffers: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        self._buffer_size = 1000  # Buffer before computing initial statistics
        
        self.feature_extractor = FeatureExtractor()
        
        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing profiles
        self._load_profiles()
    
    def learn(self, feature_set: FeatureSet) -> None:
        """
        Learn from a new feature set.
        
        Args:
            feature_set: Extracted features to learn from
        """
        source_type = feature_set.source_type
        
        if source_type not in self.profiles:
            self.profiles[source_type] = BehaviorProfile(
                source_type=source_type,
                min_samples_for_stable=self.min_samples,
            )
        
        profile = self.profiles[source_type]
        
        if profile.sample_count < self._buffer_size:
            # Buffering phase: collect samples
            for feature_name, value in feature_set.features.items():
                self._feature_buffers[source_type][feature_name].append(value)
            
            profile.sample_count += 1
            
            if profile.sample_count == self._buffer_size:
                # Compute initial statistics from buffer
                self._compute_initial_stats(source_type)
        else:
            # Online learning phase: update with exponential moving average
            self._update_stats(profile, feature_set)
        
        profile.updated_at = datetime.now()
    
    def learn_batch(self, feature_sets: List[FeatureSet]) -> None:
        """
        Learn from multiple feature sets.
        
        Args:
            feature_sets: List of feature sets to learn from
        """
        for fs in feature_sets:
            self.learn(fs)
    
    def get_profile(self, source_type: str) -> Optional[BehaviorProfile]:
        """
        Get behavioral profile for a source type.
        
        Args:
            source_type: Type of source ('log', 'process', 'network', 'metric')
            
        Returns:
            BehaviorProfile if available, None otherwise
        """
        return self.profiles.get(source_type)
    
    def get_deviation_score(
        self,
        feature_set: FeatureSet,
        weights: Optional[Dict[str, float]] = None,
    ) -> float:
        """
        Calculate how much a feature set deviates from baseline.
        
        Args:
            feature_set: Features to check
            weights: Optional feature weights (default: equal weights)
            
        Returns:
            Deviation score from 0 (normal) to 1+ (anomalous)
        """
        profile = self.profiles.get(feature_set.source_type)
        if not profile or not profile.is_stable():
            return 0.0  # Can't calculate without stable baseline
        
        deviations = []
        
        for feature_name, value in feature_set.features.items():
            if feature_name not in profile.feature_stats:
                continue
            
            stats = profile.feature_stats[feature_name]
            mean = stats.get('mean', 0.5)
            std = max(stats.get('std', 0.25), 0.01)  # Avoid division by zero
            
            # Calculate z-score
            z_score = abs(value - mean) / std
            
            # Apply weight if provided
            weight = weights.get(feature_name, 1.0) if weights else 1.0
            deviations.append(z_score * weight)
        
        if not deviations:
            return 0.0
        
        # Return normalized average deviation
        return sum(deviations) / len(deviations) / 3.0  # Divide by 3 to normalize (3 std = 1.0)
    
    def get_feature_deviations(
        self,
        feature_set: FeatureSet,
    ) -> Dict[str, Tuple[float, str]]:
        """
        Get individual feature deviations with explanations.
        
        Args:
            feature_set: Features to analyze
            
        Returns:
            Dict mapping feature name to (z_score, explanation)
        """
        profile = self.profiles.get(feature_set.source_type)
        if not profile or not profile.is_stable():
            return {}
        
        result = {}
        
        for feature_name, value in feature_set.features.items():
            if feature_name not in profile.feature_stats:
                continue
            
            stats = profile.feature_stats[feature_name]
            mean = stats.get('mean', 0.5)
            std = max(stats.get('std', 0.25), 0.01)
            
            z_score = (value - mean) / std
            
            if abs(z_score) > 2:
                if z_score > 0:
                    explanation = f"Higher than normal (value={value:.3f}, expected≈{mean:.3f}±{std:.3f})"
                else:
                    explanation = f"Lower than normal (value={value:.3f}, expected≈{mean:.3f}±{std:.3f})"
                result[feature_name] = (z_score, explanation)
        
        return result
    
    def save_profiles(self) -> None:
        """Save all profiles to disk."""
        for source_type, profile in self.profiles.items():
            profile_path = self.data_dir / f'{source_type}_profile.json'
            with open(profile_path, 'w') as f:
                json.dump(profile.to_dict(), f, indent=2)
    
    def _load_profiles(self) -> None:
        """Load profiles from disk."""
        for profile_path in self.data_dir.glob('*_profile.json'):
            try:
                with open(profile_path, 'r') as f:
                    data = json.load(f)
                    profile = BehaviorProfile.from_dict(data)
                    self.profiles[profile.source_type] = profile
            except Exception as e:
                print(f"Warning: Could not load profile {profile_path}: {e}")
    
    def _compute_initial_stats(self, source_type: str) -> None:
        """Compute initial statistics from buffer."""
        profile = self.profiles[source_type]
        buffers = self._feature_buffers[source_type]
        
        for feature_name, values in buffers.items():
            if not values:
                continue
            
            mean = statistics.mean(values)
            std = statistics.stdev(values) if len(values) > 1 else 0.1
            
            profile.feature_stats[feature_name] = {
                'mean': mean,
                'std': std,
                'min': min(values),
                'max': max(values),
                'variance': std ** 2,
            }
        
        # Clear buffer
        self._feature_buffers[source_type].clear()
    
    def _update_stats(self, profile: BehaviorProfile, feature_set: FeatureSet) -> None:
        """Update statistics with exponential moving average."""
        alpha = self.learning_rate
        
        for feature_name, value in feature_set.features.items():
            if feature_name not in profile.feature_stats:
                profile.feature_stats[feature_name] = {
                    'mean': value,
                    'std': 0.1,
                    'min': value,
                    'max': value,
                    'variance': 0.01,
                }
                continue
            
            stats = profile.feature_stats[feature_name]
            old_mean = stats['mean']
            
            # Update mean with EMA
            new_mean = (1 - alpha) * old_mean + alpha * value
            
            # Update variance with EMA
            old_variance = stats['variance']
            new_variance = (1 - alpha) * old_variance + alpha * (value - new_mean) ** 2
            
            stats['mean'] = new_mean
            stats['variance'] = new_variance
            stats['std'] = math.sqrt(new_variance)
            stats['min'] = min(stats['min'], value)
            stats['max'] = max(stats['max'], value)
        
        profile.sample_count += 1


class TimeBasedBaseline:
    """
    Time-aware baseline that accounts for daily/weekly patterns.
    
    Maintains separate profiles for different time periods to
    handle normal behavioral variations throughout the day/week.
    """
    
    def __init__(
        self,
        data_dir: Optional[Path] = None,
        hour_granularity: int = 4,  # 4-hour buckets
        separate_weekends: bool = True,
    ):
        """
        Initialize time-based baseline.
        
        Args:
            data_dir: Directory to store profiles
            hour_granularity: Hour bucket size (1, 2, 4, 6, 8, 12)
            separate_weekends: Whether to have separate weekend profiles
        """
        self.data_dir = Path(data_dir) if data_dir else Path('./data/baselines/time')
        self.hour_granularity = hour_granularity
        self.separate_weekends = separate_weekends
        
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Create learner for each time bucket
        self.learners: Dict[str, BaselineLearner] = {}
    
    def _get_time_bucket(self, timestamp: datetime) -> str:
        """Get time bucket identifier."""
        hour_bucket = timestamp.hour // self.hour_granularity
        
        if self.separate_weekends:
            day_type = 'weekend' if timestamp.weekday() >= 5 else 'weekday'
            return f"{day_type}_h{hour_bucket}"
        else:
            return f"h{hour_bucket}"
    
    def _get_learner(self, bucket: str) -> BaselineLearner:
        """Get or create learner for time bucket."""
        if bucket not in self.learners:
            bucket_dir = self.data_dir / bucket
            self.learners[bucket] = BaselineLearner(data_dir=bucket_dir)
        return self.learners[bucket]
    
    def learn(self, feature_set: FeatureSet) -> None:
        """Learn from feature set, routing to appropriate time bucket."""
        bucket = self._get_time_bucket(feature_set.timestamp)
        learner = self._get_learner(bucket)
        learner.learn(feature_set)
    
    def get_deviation_score(self, feature_set: FeatureSet) -> float:
        """Get deviation score using appropriate time bucket."""
        bucket = self._get_time_bucket(feature_set.timestamp)
        learner = self._get_learner(bucket)
        return learner.get_deviation_score(feature_set)
    
    def get_profile(self, source_type: str, timestamp: datetime) -> Optional[BehaviorProfile]:
        """Get profile for source type at specific time."""
        bucket = self._get_time_bucket(timestamp)
        learner = self._get_learner(bucket)
        return learner.get_profile(source_type)
    
    def save_all(self) -> None:
        """Save all time bucket profiles."""
        for learner in self.learners.values():
            learner.save_profiles()
