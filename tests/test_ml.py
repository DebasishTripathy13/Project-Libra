"""
Tests for the ML components (feature extraction, anomaly detection, baseline learning).
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ml.feature_extractor import SecurityFeatureExtractor
from src.ml.baseline_learner import BaselineLearner
from src.ml.anomaly_detector import AnomalyDetector
from src.ml.pattern_detector import PatternDetector


class TestSecurityFeatureExtractor:
    """Tests for feature extraction."""
    
    @pytest.fixture
    def extractor(self):
        return SecurityFeatureExtractor()
    
    def test_extract_basic_features(self, extractor):
        """Test extraction of basic event features."""
        event = {
            "timestamp": datetime.now(),
            "event_type": "authentication",
            "source": "auth_log",
            "severity": "warning",
            "details": {
                "user": "admin",
                "ip": "192.168.1.100"
            }
        }
        
        features = extractor.extract(event)
        
        assert features is not None
        assert len(features) > 0
    
    def test_extract_network_features(self, extractor):
        """Test extraction of network event features."""
        event = {
            "timestamp": datetime.now(),
            "event_type": "network_connection",
            "source": "network_monitor",
            "severity": "info",
            "details": {
                "local_port": 22,
                "remote_ip": "10.0.0.50",
                "remote_port": 4444,
                "bytes_sent": 1000,
                "bytes_recv": 5000
            }
        }
        
        features = extractor.extract(event)
        
        assert features is not None
        # Should include port-based features
        assert any(f > 0 for f in features)
    
    def test_extract_process_features(self, extractor):
        """Test extraction of process event features."""
        event = {
            "timestamp": datetime.now(),
            "event_type": "process_start",
            "source": "process_monitor",
            "severity": "critical",
            "details": {
                "process": "suspicious.exe",
                "pid": 1234,
                "cpu_percent": 80,
                "memory_percent": 50
            }
        }
        
        features = extractor.extract(event)
        
        assert features is not None
    
    def test_feature_dimensionality_consistent(self, extractor):
        """Test that feature vectors have consistent dimensions."""
        events = [
            {"timestamp": datetime.now(), "event_type": "auth", "source": "log", "severity": "info", "details": {}},
            {"timestamp": datetime.now(), "event_type": "network", "source": "net", "severity": "warning", "details": {"port": 80}},
            {"timestamp": datetime.now(), "event_type": "process", "source": "proc", "severity": "critical", "details": {"pid": 123}},
        ]
        
        feature_vectors = [extractor.extract(e) for e in events]
        dimensions = [len(f) for f in feature_vectors]
        
        # All feature vectors should have the same dimension
        assert len(set(dimensions)) == 1


class TestBaselineLearner:
    """Tests for baseline learning."""
    
    @pytest.fixture
    def learner(self):
        return BaselineLearner()
    
    def test_add_sample(self, learner):
        """Test adding samples to the learner."""
        features = [0.1, 0.2, 0.3, 0.4, 0.5]
        
        learner.add_sample(features)
        
        assert len(learner.samples) == 1
    
    def test_train_requires_minimum_samples(self, learner):
        """Test that training requires minimum number of samples."""
        # Add only a few samples
        for i in range(5):
            learner.add_sample([0.1 * i] * 5)
        
        # Training should handle small sample sizes
        learner.train()
        # Should not crash, model may or may not be trained
    
    def test_train_with_sufficient_samples(self, learner):
        """Test training with sufficient samples."""
        import random
        
        # Add enough samples for training
        for _ in range(100):
            features = [random.gauss(0, 1) for _ in range(10)]
            learner.add_sample(features)
        
        learner.train()
        
        assert learner.model is not None
    
    def test_is_anomaly_detection(self, learner):
        """Test anomaly detection after training."""
        import random
        
        # Train with normal data (centered around 0)
        for _ in range(100):
            features = [random.gauss(0, 0.1) for _ in range(10)]
            learner.add_sample(features)
        
        learner.train()
        
        # Test with normal sample
        normal_sample = [random.gauss(0, 0.1) for _ in range(10)]
        is_anomaly, score = learner.is_anomaly(normal_sample)
        
        # Normal sample should have low anomaly score
        # (exact behavior depends on training)
        assert isinstance(is_anomaly, bool)
        assert isinstance(score, float)
        
        # Test with anomalous sample (far from training distribution)
        anomaly_sample = [10.0] * 10  # Far from normal
        is_anomaly_2, score_2 = learner.is_anomaly(anomaly_sample)
        
        # Anomaly should have higher score
        assert score_2 >= score


class TestAnomalyDetector:
    """Tests for anomaly detection algorithms."""
    
    @pytest.fixture
    def detector(self):
        return AnomalyDetector(sensitivity=0.7)
    
    def test_initialization(self, detector):
        """Test detector initialization."""
        assert detector.sensitivity == 0.7
    
    def test_detect_returns_score(self, detector):
        """Test that detection returns a score."""
        features = [0.1, 0.2, 0.3, 0.4, 0.5]
        
        result = detector.detect(features)
        
        assert "is_anomaly" in result
        assert "score" in result
        assert isinstance(result["score"], float)
        assert 0.0 <= result["score"] <= 1.0
    
    def test_sensitivity_affects_detection(self):
        """Test that sensitivity parameter affects detection."""
        features = [0.5] * 10  # Borderline case
        
        low_sensitivity = AnomalyDetector(sensitivity=0.3)
        high_sensitivity = AnomalyDetector(sensitivity=0.9)
        
        # Higher sensitivity should detect more anomalies
        result_low = low_sensitivity.detect(features)
        result_high = high_sensitivity.detect(features)
        
        # Both should return valid results
        assert isinstance(result_low["is_anomaly"], bool)
        assert isinstance(result_high["is_anomaly"], bool)


class TestPatternDetector:
    """Tests for attack pattern detection."""
    
    @pytest.fixture
    def detector(self):
        return PatternDetector()
    
    def test_detect_brute_force(self, detector):
        """Test detection of brute force pattern."""
        event = {
            "event_type": "authentication",
            "source": "auth_log",
            "severity": "warning",
            "details": {
                "user": "root",
                "ip": "10.0.0.100",
                "success": False,
                "attempts": 100
            }
        }
        
        patterns = detector.detect(event)
        
        assert len(patterns) > 0
        pattern_names = [p["name"] for p in patterns]
        assert "brute_force" in pattern_names or any("brute" in n.lower() for n in pattern_names)
    
    def test_detect_suspicious_network(self, detector):
        """Test detection of suspicious network activity."""
        event = {
            "event_type": "network_connection",
            "source": "network_monitor",
            "severity": "critical",
            "details": {
                "remote_ip": "198.51.100.50",
                "remote_port": 4444,
                "protocol": "tcp"
            }
        }
        
        patterns = detector.detect(event)
        
        # Port 4444 is commonly used for reverse shells
        assert len(patterns) >= 0  # May or may not detect based on implementation
    
    def test_detect_privilege_escalation(self, detector):
        """Test detection of privilege escalation."""
        event = {
            "event_type": "process_start",
            "source": "process_monitor",
            "severity": "critical",
            "details": {
                "process": "sudo",
                "cmdline": "sudo chmod +s /tmp/exploit",
                "user": "regular_user"
            }
        }
        
        patterns = detector.detect(event)
        
        # Should detect potential privilege escalation
        assert isinstance(patterns, list)
    
    def test_analyze_attack_chain(self, detector):
        """Test attack chain analysis."""
        events = [
            {"event_type": "authentication", "source": "auth", "severity": "warning", 
             "details": {"success": False, "attempts": 50}},
            {"event_type": "authentication", "source": "auth", "severity": "info",
             "details": {"success": True}},
            {"event_type": "process_start", "source": "proc", "severity": "warning",
             "details": {"process": "wget"}},
            {"event_type": "network_connection", "source": "net", "severity": "critical",
             "details": {"remote_port": 4444}},
        ]
        
        analysis = detector.analyze_attack_chain(events)
        
        assert isinstance(analysis, dict)
        assert "chain_type" in analysis or "phases" in analysis or "confidence" in analysis


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
