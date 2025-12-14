"""
ML Behavioral Analysis Package for ProjectLibra.

This package provides machine learning capabilities for:
- Baseline behavior learning
- Anomaly detection
- Pattern recognition
- Behavioral profiling
"""

from .baseline_learner import BaselineLearner, BehaviorProfile
from .anomaly_detector import AnomalyDetector, AnomalyResult
from .feature_extractor import FeatureExtractor, FeatureSet
from .pattern_detector import PatternDetector, PatternMatch

# Alias for backward compatibility
SecurityFeatureExtractor = FeatureExtractor

__all__ = [
    'BaselineLearner',
    'BehaviorProfile',
    'AnomalyDetector',
    'AnomalyResult',
    'FeatureExtractor',
    'SecurityFeatureExtractor',  # Alias
    'FeatureSet',
    'PatternDetector',
    'PatternMatch',
]
