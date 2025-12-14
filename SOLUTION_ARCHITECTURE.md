# ProjectLibra - Detailed Solution Architecture

## Executive Summary

ProjectLibra is an **Agentic AI-Driven Unified Host Security Platform** that provides:
- Real-time behavioral analysis and anomaly detection
- LLM-powered log intelligence
- ML-based threat detection
- Intelligent patch management
- **Tamper-proof dual-database audit logging system**

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           USER INTERFACES                                    │
│  ┌──────────────┐  ┌──────────────────┐  ┌─────────────────────────────┐   │
│  │   CLI Tool   │  │  Web Dashboard   │  │  JSON API (SIEM/SOAR)       │   │
│  └──────────────┘  └──────────────────┘  └─────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        AGENTIC AI REASONING LAYER                            │
│  ┌────────────────┐ ┌───────────────┐ ┌──────────────┐ ┌────────────────┐  │
│  │ Observation    │ │ Correlation   │ │ Threat       │ │ Maintenance    │  │
│  │ Agent          │ │ Agent         │ │ Reasoning    │ │ Agent          │  │
│  │                │ │               │ │ Agent        │ │                │  │
│  └────────────────┘ └───────────────┘ └──────────────┘ └────────────────┘  │
│                           ┌────────────────┐                                │
│                           │ Learning Agent │                                │
│                           └────────────────┘                                │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    INTELLIGENCE & DETECTION LAYER                            │
│  ┌──────────────────────┐  ┌────────────────────┐  ┌────────────────────┐  │
│  │ LLM Log Intelligence │  │ ML Behavioral      │  │ Anomaly Detection  │  │
│  │ (OpenAI/Gemini/      │  │ Baseline Engine    │  │ Engine             │  │
│  │  Groq/Ollama)        │  │                    │  │                    │  │
│  └──────────────────────┘  └────────────────────┘  └────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DATA PROCESSING & STORAGE LAYER                           │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    DUAL DATABASE SECURITY SYSTEM                     │   │
│  │  ┌─────────────────────────┐    ┌─────────────────────────────┐    │   │
│  │  │   PRIMARY DATABASE      │    │   IMMUTABLE BACKUP DATABASE │    │   │
│  │  │   (Main Operations)     │    │   (Tamper-Proof Audit Log)  │    │   │
│  │  │                         │    │                              │    │   │
│  │  │  • Read/Write Access    │    │  • Write-Once/Read-Many     │    │   │
│  │  │  • Real-time queries    │    │  • Cryptographic hashing    │    │   │
│  │  │  • Attacker target      │    │  • Blockchain-style chain   │    │   │
│  │  │                         │    │  • Separate credentials     │    │   │
│  │  └─────────────────────────┘    └─────────────────────────────┘    │   │
│  │              │                              │                       │   │
│  │              └──────────┬───────────────────┘                       │   │
│  │                         ▼                                           │   │
│  │            ┌─────────────────────────┐                              │   │
│  │            │  INTEGRITY VALIDATOR    │                              │   │
│  │            │  (Continuous Compare)   │                              │   │
│  │            │  Detects Manipulation   │                              │   │
│  │            └─────────────────────────┘                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DATA COLLECTION LAYER (Cross-Platform)                    │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐   │
│  │ System Logs  │ │ Process      │ │ Network      │ │ Patch/Update     │   │
│  │ Collector    │ │ Monitor      │ │ Monitor      │ │ Tracker          │   │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────────┘   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐   │
│  │ CPU/RAM/Disk │ │ File System  │ │ User Activity│ │ Security Events  │   │
│  │ Metrics      │ │ Watcher      │ │ Monitor      │ │ (Login/Auth)     │   │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Dual Database Security System (Detailed)

### 2.1 Problem: Log Manipulation by Attackers

When attackers gain access to a system, they often:
1. Delete or modify logs to cover their tracks
2. Alter timestamps to confuse forensic analysis
3. Insert false entries to mislead investigators
4. Corrupt database integrity

### 2.2 Solution: Immutable Backup Database

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    DUAL DATABASE ARCHITECTURE                               │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                         WRITE PATH                                   │  │
│   │                                                                      │  │
│   │   Event ──► Hash Generator ──┬──► Primary DB (Normal Write)         │  │
│   │                              │                                       │  │
│   │                              └──► Backup DB (Append-Only + Hash)     │  │
│   │                                        │                             │  │
│   │                                        ▼                             │  │
│   │                              ┌─────────────────────┐                 │  │
│   │                              │ Chain Hash:         │                 │  │
│   │                              │ H(n) = SHA256(      │                 │  │
│   │                              │   H(n-1) + Data(n)) │                 │  │
│   │                              └─────────────────────┘                 │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                       INTEGRITY CHECK PATH                           │  │
│   │                                                                      │  │
│   │   ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │  │
│   │   │ Primary DB   │◄──►│  Comparator  │◄──►│ Backup DB            │  │  │
│   │   │ Records      │    │              │    │ (Hash Verified)      │  │  │
│   │   └──────────────┘    └──────────────┘    └──────────────────────┘  │  │
│   │                              │                                       │  │
│   │                              ▼                                       │  │
│   │                    ┌─────────────────────┐                          │  │
│   │                    │ MISMATCH DETECTED?  │                          │  │
│   │                    │  ┌─────┐   ┌─────┐  │                          │  │
│   │                    │  │ NO  │   │ YES │  │                          │  │
│   │                    │  └──┬──┘   └──┬──┘  │                          │  │
│   │                    │     │         │     │                          │  │
│   │                    │     ▼         ▼     │                          │  │
│   │                    │  Continue   ALERT!  │                          │  │
│   │                    │            + FLAG   │                          │  │
│   │                    └─────────────────────┘                          │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
```

### 2.3 Database Separation Strategies

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    SECURITY ISOLATION LEVELS                                │
│                                                                             │
│  LEVEL 1: Logical Separation (Same Server)                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Server                                                              │   │
│  │  ├── primary_db (User: app_user, Full CRUD)                         │   │
│  │  └── backup_db  (User: audit_user, INSERT ONLY)                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  LEVEL 2: Physical Separation (Different Servers)                          │
│  ┌──────────────────────┐    ┌──────────────────────────────────────┐     │
│  │  Main Server         │    │  Backup Server (Hardened)            │     │
│  │  └── primary_db      │    │  └── backup_db                       │     │
│  │      (app access)    │    │      (write-only API endpoint)       │     │
│  └──────────────────────┘    └──────────────────────────────────────┘     │
│                                                                             │
│  LEVEL 3: Network Isolation (Air-Gapped/Different Network)                 │
│  ┌──────────────────────┐    ┌──────────────────────────────────────┐     │
│  │  Production Network  │    │  Audit Network (Isolated)            │     │
│  │  └── primary_db      │───►│  └── backup_db                       │     │
│  │                      │    │      (One-way data diode)            │     │
│  └──────────────────────┘    └──────────────────────────────────────┘     │
│                                                                             │
│  LEVEL 4: External Service (Cloud/Third-Party)                             │
│  ┌──────────────────────┐    ┌──────────────────────────────────────┐     │
│  │  Local System        │    │  Cloud Immutable Storage             │     │
│  │  └── primary_db      │───►│  └── AWS S3 Object Lock              │     │
│  │                      │    │  └── Azure Immutable Blob            │     │
│  │                      │    │  └── GCP Bucket Lock                 │     │
│  └──────────────────────┘    └──────────────────────────────────────┘     │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Specifications

### 3.1 Data Collection Layer

```python
# collector/base_collector.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Any, Optional
import hashlib
import json

@dataclass
class CollectedEvent:
    """Standardized event structure for all collectors"""
    event_id: str
    timestamp: datetime
    source: str           # 'syslog', 'process', 'network', 'metrics'
    event_type: str       # 'login', 'process_start', 'connection', etc.
    severity: str         # 'info', 'warning', 'error', 'critical'
    host_id: str
    os_type: str          # 'linux', 'windows', 'macos'
    raw_data: Dict[str, Any]
    normalized_data: Dict[str, Any]
    hash: str             # SHA256 of event content
    
    def compute_hash(self) -> str:
        """Compute cryptographic hash of event content"""
        content = json.dumps({
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'event_type': self.event_type,
            'raw_data': self.raw_data
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

class BaseCollector(ABC):
    """Abstract base class for all collectors"""
    
    @abstractmethod
    def collect(self) -> list[CollectedEvent]:
        """Collect events from the source"""
        pass
    
    @abstractmethod
    def get_source_name(self) -> str:
        """Return the collector source identifier"""
        pass
```

### 3.2 Dual Database System Implementation

```python
# database/dual_db_manager.py
import hashlib
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
import sqlite3
import threading
from enum import Enum

class IntegrityStatus(Enum):
    VALID = "valid"
    TAMPERED = "tampered"
    MISSING_PRIMARY = "missing_in_primary"
    MISSING_BACKUP = "missing_in_backup"
    HASH_MISMATCH = "hash_mismatch"

@dataclass
class AuditRecord:
    """Single audit log entry with chain hash"""
    record_id: str
    timestamp: datetime
    event_type: str
    event_data: Dict[str, Any]
    content_hash: str           # Hash of the event data
    previous_hash: str          # Hash of previous record (blockchain-style)
    chain_hash: str             # Hash of (previous_hash + content_hash)
    
@dataclass
class IntegrityReport:
    """Report from integrity check"""
    check_timestamp: datetime
    total_records_checked: int
    valid_records: int
    tampered_records: int
    missing_records: int
    issues: List[Dict[str, Any]] = field(default_factory=list)
    overall_status: str = "unknown"

class ImmutableBackupDB:
    """
    Immutable backup database with:
    - Append-only operations
    - Cryptographic hash chains
    - Separate credentials
    - Write-once read-many (WORM) semantics
    """
    
    def __init__(self, db_path: str, credentials: Dict[str, str]):
        self.db_path = db_path
        self.credentials = credentials
        self._lock = threading.Lock()
        self._last_chain_hash = self._get_genesis_hash()
        self._init_db()
    
    def _get_genesis_hash(self) -> str:
        """Genesis block hash for the chain"""
        return hashlib.sha256(b"PROJECTLIBRA_GENESIS_BLOCK").hexdigest()
    
    def _init_db(self):
        """Initialize the backup database with restricted schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create immutable audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                chain_hash TEXT NOT NULL,
                inserted_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create index for fast lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_record_id ON audit_log(record_id)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp)
        ''')
        
        # Create triggers to PREVENT updates and deletes
        cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS prevent_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'Updates are not allowed on immutable audit log');
            END
        ''')
        
        cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS prevent_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'Deletes are not allowed on immutable audit log');
            END
        ''')
        
        conn.commit()
        conn.close()
        
        # Load the last chain hash
        self._load_last_chain_hash()
    
    def _load_last_chain_hash(self):
        """Load the most recent chain hash for continuity"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1')
        result = cursor.fetchone()
        conn.close()
        
        if result:
            self._last_chain_hash = result[0]
    
    def _compute_content_hash(self, event_data: Dict[str, Any]) -> str:
        """Compute hash of event content"""
        content = json.dumps(event_data, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _compute_chain_hash(self, previous_hash: str, content_hash: str) -> str:
        """Compute chain hash linking to previous record"""
        combined = f"{previous_hash}{content_hash}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def append_record(self, record_id: str, event_type: str, 
                      event_data: Dict[str, Any], timestamp: datetime) -> AuditRecord:
        """
        Append a new record to the immutable log.
        This is the ONLY write operation allowed.
        """
        with self._lock:
            content_hash = self._compute_content_hash(event_data)
            previous_hash = self._last_chain_hash
            chain_hash = self._compute_chain_hash(previous_hash, content_hash)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    INSERT INTO audit_log 
                    (record_id, timestamp, event_type, event_data, 
                     content_hash, previous_hash, chain_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    record_id,
                    timestamp.isoformat(),
                    event_type,
                    json.dumps(event_data, default=str),
                    content_hash,
                    previous_hash,
                    chain_hash
                ))
                conn.commit()
                self._last_chain_hash = chain_hash
                
                return AuditRecord(
                    record_id=record_id,
                    timestamp=timestamp,
                    event_type=event_type,
                    event_data=event_data,
                    content_hash=content_hash,
                    previous_hash=previous_hash,
                    chain_hash=chain_hash
                )
            finally:
                conn.close()
    
    def verify_chain_integrity(self) -> bool:
        """Verify the entire hash chain is intact"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT content_hash, previous_hash, chain_hash 
            FROM audit_log ORDER BY id ASC
        ''')
        
        expected_previous = self._get_genesis_hash()
        
        for row in cursor.fetchall():
            content_hash, previous_hash, chain_hash = row
            
            # Verify previous hash links correctly
            if previous_hash != expected_previous:
                conn.close()
                return False
            
            # Verify chain hash is correct
            expected_chain = self._compute_chain_hash(previous_hash, content_hash)
            if chain_hash != expected_chain:
                conn.close()
                return False
            
            expected_previous = chain_hash
        
        conn.close()
        return True
    
    def get_record(self, record_id: str) -> Optional[AuditRecord]:
        """Retrieve a specific record by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT record_id, timestamp, event_type, event_data,
                   content_hash, previous_hash, chain_hash
            FROM audit_log WHERE record_id = ?
        ''', (record_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return AuditRecord(
                record_id=row[0],
                timestamp=datetime.fromisoformat(row[1]),
                event_type=row[2],
                event_data=json.loads(row[3]),
                content_hash=row[4],
                previous_hash=row[5],
                chain_hash=row[6]
            )
        return None


class PrimaryDB:
    """
    Primary database for normal operations.
    Full CRUD operations allowed.
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                host_id TEXT NOT NULL,
                raw_data TEXT NOT NULL,
                normalized_data TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tables for ML models, alerts, etc.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS behavioral_baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id TEXT NOT NULL,
                metric_type TEXT NOT NULL,
                baseline_data TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                event_ids TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT DEFAULT 'open',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def insert_event(self, event: 'CollectedEvent') -> bool:
        """Insert a new event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO events 
                (event_id, timestamp, source, event_type, severity, 
                 host_id, raw_data, normalized_data, content_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.event_id,
                event.timestamp.isoformat(),
                event.source,
                event.event_type,
                event.severity,
                event.host_id,
                json.dumps(event.raw_data),
                json.dumps(event.normalized_data),
                event.hash
            ))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error inserting event: {e}")
            return False
        finally:
            conn.close()
    
    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an event by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM events WHERE event_id = ?', (event_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'event_id': row[1],
                'timestamp': row[2],
                'source': row[3],
                'event_type': row[4],
                'severity': row[5],
                'host_id': row[6],
                'raw_data': json.loads(row[7]),
                'normalized_data': json.loads(row[8]),
                'content_hash': row[9]
            }
        return None


class DualDatabaseManager:
    """
    Manager that coordinates writes to both databases
    and performs integrity validation.
    """
    
    def __init__(self, 
                 primary_db_path: str,
                 backup_db_path: str,
                 backup_credentials: Dict[str, str]):
        self.primary_db = PrimaryDB(primary_db_path)
        self.backup_db = ImmutableBackupDB(backup_db_path, backup_credentials)
        self._integrity_check_interval = 300  # 5 minutes
    
    def store_event(self, event: 'CollectedEvent') -> bool:
        """
        Store event in both databases atomically.
        Returns True if both writes succeed.
        """
        # Write to primary (normal operation)
        primary_success = self.primary_db.insert_event(event)
        
        # Write to backup (immutable, append-only)
        backup_record = self.backup_db.append_record(
            record_id=event.event_id,
            event_type=event.event_type,
            event_data={
                'source': event.source,
                'severity': event.severity,
                'host_id': event.host_id,
                'raw_data': event.raw_data,
                'content_hash': event.hash
            },
            timestamp=event.timestamp
        )
        
        return primary_success and backup_record is not None
    
    def check_integrity(self, event_id: str) -> IntegrityStatus:
        """
        Check if a specific event has been tampered with
        by comparing primary and backup databases.
        """
        primary_event = self.primary_db.get_event(event_id)
        backup_record = self.backup_db.get_record(event_id)
        
        if not primary_event and not backup_record:
            return IntegrityStatus.VALID  # Event doesn't exist
        
        if not primary_event:
            return IntegrityStatus.MISSING_PRIMARY  # TAMPERED: Deleted from primary
        
        if not backup_record:
            return IntegrityStatus.MISSING_BACKUP  # Error: Should never happen
        
        # Compare content hashes
        if primary_event['content_hash'] != backup_record.event_data['content_hash']:
            return IntegrityStatus.HASH_MISMATCH  # TAMPERED: Content modified
        
        return IntegrityStatus.VALID
    
    def full_integrity_audit(self) -> IntegrityReport:
        """
        Perform a full integrity audit comparing all records.
        This detects any tampering in the primary database.
        """
        report = IntegrityReport(
            check_timestamp=datetime.now(),
            total_records_checked=0,
            valid_records=0,
            tampered_records=0,
            missing_records=0
        )
        
        # First, verify the backup chain integrity
        if not self.backup_db.verify_chain_integrity():
            report.overall_status = "CRITICAL: Backup chain compromised"
            report.issues.append({
                'type': 'chain_integrity_failure',
                'message': 'The immutable backup hash chain has been compromised'
            })
            return report
        
        # Get all records from backup (source of truth)
        conn = sqlite3.connect(self.backup_db.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT record_id FROM audit_log')
        backup_ids = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        for record_id in backup_ids:
            report.total_records_checked += 1
            status = self.check_integrity(record_id)
            
            if status == IntegrityStatus.VALID:
                report.valid_records += 1
            elif status == IntegrityStatus.MISSING_PRIMARY:
                report.missing_records += 1
                report.issues.append({
                    'type': 'deleted_from_primary',
                    'record_id': record_id,
                    'message': f'Record {record_id} was deleted from primary DB'
                })
            elif status == IntegrityStatus.HASH_MISMATCH:
                report.tampered_records += 1
                report.issues.append({
                    'type': 'content_modified',
                    'record_id': record_id,
                    'message': f'Record {record_id} content was modified in primary DB'
                })
        
        # Set overall status
        if report.tampered_records > 0 or report.missing_records > 0:
            report.overall_status = "ALERT: Tampering Detected"
        else:
            report.overall_status = "OK: All records verified"
        
        return report
```

### 3.3 Integrity Monitor Service

```python
# services/integrity_monitor.py
import asyncio
import logging
from datetime import datetime
from typing import Callable, Optional

class IntegrityMonitorService:
    """
    Continuous monitoring service that:
    1. Periodically checks database integrity
    2. Raises alerts on tampering detection
    3. Provides real-time tamper notifications
    """
    
    def __init__(self, 
                 dual_db_manager: 'DualDatabaseManager',
                 check_interval_seconds: int = 300,
                 alert_callback: Optional[Callable] = None):
        self.db_manager = dual_db_manager
        self.check_interval = check_interval_seconds
        self.alert_callback = alert_callback
        self.logger = logging.getLogger(__name__)
        self._running = False
        self._last_report = None
    
    async def start(self):
        """Start the integrity monitoring loop"""
        self._running = True
        self.logger.info("Integrity Monitor Service started")
        
        while self._running:
            try:
                await self._perform_check()
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                self.logger.error(f"Integrity check error: {e}")
                await asyncio.sleep(60)  # Wait before retry
    
    async def _perform_check(self):
        """Perform integrity check and handle results"""
        self.logger.info("Starting integrity audit...")
        
        report = self.db_manager.full_integrity_audit()
        self._last_report = report
        
        self.logger.info(f"Integrity check complete: {report.overall_status}")
        self.logger.info(f"  - Total records: {report.total_records_checked}")
        self.logger.info(f"  - Valid: {report.valid_records}")
        self.logger.info(f"  - Tampered: {report.tampered_records}")
        self.logger.info(f"  - Missing: {report.missing_records}")
        
        # Raise alert if tampering detected
        if report.tampered_records > 0 or report.missing_records > 0:
            await self._raise_tampering_alert(report)
    
    async def _raise_tampering_alert(self, report: 'IntegrityReport'):
        """Raise high-priority tampering alert"""
        alert_data = {
            'alert_type': 'DATABASE_TAMPERING_DETECTED',
            'severity': 'CRITICAL',
            'timestamp': datetime.now().isoformat(),
            'tampered_count': report.tampered_records,
            'missing_count': report.missing_records,
            'issues': report.issues,
            'recommended_action': [
                'Isolate affected system immediately',
                'Preserve backup database for forensics',
                'Review recent access logs',
                'Initiate incident response procedure'
            ]
        }
        
        self.logger.critical(f"TAMPERING ALERT: {alert_data}")
        
        if self.alert_callback:
            await self.alert_callback(alert_data)
    
    def stop(self):
        """Stop the monitoring service"""
        self._running = False
        self.logger.info("Integrity Monitor Service stopped")
    
    def get_last_report(self) -> Optional['IntegrityReport']:
        """Get the most recent integrity report"""
        return self._last_report
```

---

## 4. Agentic AI Layer

### 4.1 Agent Architecture

```python
# agents/base_agent.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from enum import Enum

class AgentAction(Enum):
    OBSERVE = "observe"
    ANALYZE = "analyze"
    CORRELATE = "correlate"
    ALERT = "alert"
    REMEDIATE = "remediate"
    LEARN = "learn"

@dataclass
class AgentDecision:
    """Represents a decision made by an agent"""
    agent_id: str
    action: AgentAction
    confidence: float
    reasoning: str
    evidence: List[Dict[str, Any]]
    recommended_actions: List[str]
    timestamp: str

class BaseAgent(ABC):
    """Base class for all AI agents"""
    
    def __init__(self, agent_id: str, llm_client: Any):
        self.agent_id = agent_id
        self.llm_client = llm_client
        self.memory = []  # Agent's working memory
    
    @abstractmethod
    async def process(self, input_data: Dict[str, Any]) -> AgentDecision:
        """Process input and return a decision"""
        pass
    
    @abstractmethod
    def get_capabilities(self) -> List[str]:
        """Return list of agent capabilities"""
        pass


# agents/threat_reasoning_agent.py
class ThreatReasoningAgent(BaseAgent):
    """
    Agent responsible for evaluating security threats
    using multi-step reasoning.
    """
    
    THREAT_ASSESSMENT_PROMPT = """
    You are a security threat analyst. Analyze the following event data
    and determine if it represents a security threat.
    
    Event Data:
    {event_data}
    
    Behavioral Baseline:
    {baseline_data}
    
    Recent Related Events:
    {related_events}
    
    Provide your analysis in the following format:
    1. Threat Assessment: [HIGH/MEDIUM/LOW/NONE]
    2. Confidence: [0-100]%
    3. Reasoning: [Your detailed reasoning]
    4. Indicators: [List of suspicious indicators]
    5. Recommended Actions: [List of recommended responses]
    """
    
    async def process(self, input_data: Dict[str, Any]) -> AgentDecision:
        # Prepare context for LLM
        prompt = self.THREAT_ASSESSMENT_PROMPT.format(
            event_data=input_data.get('event'),
            baseline_data=input_data.get('baseline'),
            related_events=input_data.get('related_events', [])
        )
        
        # Get LLM assessment
        response = await self.llm_client.analyze(prompt)
        
        # Parse response and create decision
        return AgentDecision(
            agent_id=self.agent_id,
            action=AgentAction.ANALYZE,
            confidence=response.confidence,
            reasoning=response.reasoning,
            evidence=response.indicators,
            recommended_actions=response.actions,
            timestamp=datetime.now().isoformat()
        )
    
    def get_capabilities(self) -> List[str]:
        return [
            "threat_assessment",
            "malware_detection",
            "anomaly_classification",
            "attack_chain_analysis"
        ]


# agents/correlation_agent.py
class CorrelationAgent(BaseAgent):
    """
    Agent that correlates events across different sources
    to identify attack patterns.
    """
    
    async def process(self, input_data: Dict[str, Any]) -> AgentDecision:
        events = input_data.get('events', [])
        
        # Use LLM for semantic correlation
        correlation_prompt = f"""
        Analyze these events for correlation patterns:
        {events}
        
        Look for:
        1. Temporal correlations (events happening in sequence)
        2. Causal relationships (one event triggering another)
        3. Attack chain patterns (reconnaissance → exploitation → persistence)
        4. Lateral movement indicators
        """
        
        response = await self.llm_client.analyze(correlation_prompt)
        
        return AgentDecision(
            agent_id=self.agent_id,
            action=AgentAction.CORRELATE,
            confidence=response.confidence,
            reasoning=response.analysis,
            evidence=response.correlated_events,
            recommended_actions=response.actions,
            timestamp=datetime.now().isoformat()
        )
    
    def get_capabilities(self) -> List[str]:
        return [
            "event_correlation",
            "attack_chain_detection",
            "lateral_movement_detection"
        ]
```

### 4.2 Agent Orchestrator

```python
# agents/orchestrator.py
class AgentOrchestrator:
    """
    Coordinates multiple AI agents for comprehensive
    security analysis and response.
    """
    
    def __init__(self, llm_client: Any, dual_db: 'DualDatabaseManager'):
        self.llm_client = llm_client
        self.dual_db = dual_db
        
        # Initialize all agents
        self.agents = {
            'observation': ObservationAgent('obs-001', llm_client),
            'correlation': CorrelationAgent('corr-001', llm_client),
            'threat': ThreatReasoningAgent('threat-001', llm_client),
            'maintenance': MaintenanceAgent('maint-001', llm_client),
            'learning': LearningAgent('learn-001', llm_client)
        }
    
    async def process_event(self, event: 'CollectedEvent') -> Dict[str, Any]:
        """
        Process an event through the agent pipeline.
        """
        results = {}
        
        # Step 1: Observation Agent - Initial classification
        obs_result = await self.agents['observation'].process({
            'event': event
        })
        results['observation'] = obs_result
        
        # Step 2: If suspicious, correlate with other events
        if obs_result.confidence > 0.5:
            related_events = await self._get_related_events(event)
            corr_result = await self.agents['correlation'].process({
                'events': [event] + related_events
            })
            results['correlation'] = corr_result
        
        # Step 3: Threat assessment
        if results.get('correlation', {}).confidence > 0.6:
            baseline = await self._get_baseline(event.host_id)
            threat_result = await self.agents['threat'].process({
                'event': event,
                'baseline': baseline,
                'related_events': results.get('correlation', {}).evidence
            })
            results['threat'] = threat_result
        
        # Step 4: Learning agent updates baselines
        await self.agents['learning'].process({
            'event': event,
            'analysis_results': results
        })
        
        return results
```

---

## 5. LLM Integration Layer

### 5.1 Pluggable LLM Backend

```python
# llm/llm_client.py
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class LLMResponse:
    """Standardized LLM response"""
    content: str
    confidence: float
    reasoning: str
    structured_data: Optional[Dict[str, Any]] = None

class BaseLLMClient(ABC):
    """Abstract base for LLM clients"""
    
    @abstractmethod
    async def analyze(self, prompt: str) -> LLMResponse:
        pass
    
    @abstractmethod
    async def classify(self, text: str, categories: list) -> str:
        pass

class OpenAIClient(BaseLLMClient):
    """OpenAI GPT integration"""
    
    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.api_key = api_key
        self.model = model
    
    async def analyze(self, prompt: str) -> LLMResponse:
        # Implementation for OpenAI API
        pass

class OllamaClient(BaseLLMClient):
    """Local Ollama integration for privacy-preserving analysis"""
    
    def __init__(self, base_url: str = "http://localhost:11434", 
                 model: str = "llama2"):
        self.base_url = base_url
        self.model = model
    
    async def analyze(self, prompt: str) -> LLMResponse:
        # Implementation for local Ollama
        pass

class LLMFactory:
    """Factory for creating LLM clients"""
    
    @staticmethod
    def create(provider: str, config: Dict[str, Any]) -> BaseLLMClient:
        if provider == "openai":
            return OpenAIClient(config['api_key'], config.get('model', 'gpt-4'))
        elif provider == "ollama":
            return OllamaClient(config.get('base_url'), config.get('model'))
        elif provider == "groq":
            return GroqClient(config['api_key'], config.get('model'))
        elif provider == "gemini":
            return GeminiClient(config['api_key'], config.get('model'))
        else:
            raise ValueError(f"Unknown LLM provider: {provider}")
```

---

## 6. ML Behavioral Engine

### 6.1 Baseline Learning

```python
# ml/behavioral_engine.py
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class BehavioralBaseline:
    """Learned behavioral baseline for a host"""
    host_id: str
    cpu_patterns: np.ndarray
    memory_patterns: np.ndarray
    network_patterns: np.ndarray
    process_patterns: Dict[str, float]
    time_patterns: Dict[int, Dict[str, float]]  # Hour -> metrics
    anomaly_threshold: float
    last_updated: str

class BehavioralEngine:
    """
    ML engine for learning and detecting behavioral anomalies.
    """
    
    def __init__(self):
        self.isolation_forests = {}  # Per-host anomaly detectors
        self.scalers = {}
        self.baselines = {}
    
    def learn_baseline(self, host_id: str, 
                       historical_data: List[Dict[str, Any]]) -> BehavioralBaseline:
        """Learn behavioral baseline from historical data"""
        
        # Extract features
        features = self._extract_features(historical_data)
        
        # Fit scaler
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)
        self.scalers[host_id] = scaler
        
        # Train isolation forest for anomaly detection
        iso_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        iso_forest.fit(scaled_features)
        self.isolation_forests[host_id] = iso_forest
        
        # Calculate baseline statistics
        baseline = BehavioralBaseline(
            host_id=host_id,
            cpu_patterns=np.mean(features[:, 0:3], axis=0),
            memory_patterns=np.mean(features[:, 3:6], axis=0),
            network_patterns=np.mean(features[:, 6:10], axis=0),
            process_patterns=self._calculate_process_patterns(historical_data),
            time_patterns=self._calculate_time_patterns(historical_data),
            anomaly_threshold=-0.5,
            last_updated=datetime.now().isoformat()
        )
        
        self.baselines[host_id] = baseline
        return baseline
    
    def detect_anomaly(self, host_id: str, 
                       current_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect if current behavior is anomalous"""
        
        if host_id not in self.isolation_forests:
            return {'is_anomaly': False, 'reason': 'No baseline available'}
        
        features = self._extract_single_features(current_data)
        scaled = self.scalers[host_id].transform([features])
        
        score = self.isolation_forests[host_id].decision_function(scaled)[0]
        prediction = self.isolation_forests[host_id].predict(scaled)[0]
        
        is_anomaly = prediction == -1
        
        # Calculate deviation from baseline
        baseline = self.baselines[host_id]
        deviations = self._calculate_deviations(features, baseline)
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': float(score),
            'deviations': deviations,
            'confidence': abs(score) / 0.5,  # Normalize confidence
            'baseline_comparison': {
                'cpu': self._compare_to_baseline(features[0:3], baseline.cpu_patterns),
                'memory': self._compare_to_baseline(features[3:6], baseline.memory_patterns),
                'network': self._compare_to_baseline(features[6:10], baseline.network_patterns)
            }
        }
    
    def _extract_features(self, data: List[Dict]) -> np.ndarray:
        """Extract numerical features from event data"""
        features = []
        for d in data:
            features.append([
                d.get('cpu_percent', 0),
                d.get('cpu_count_active', 0),
                d.get('cpu_freq', 0),
                d.get('memory_percent', 0),
                d.get('memory_used', 0),
                d.get('swap_percent', 0),
                d.get('network_bytes_sent', 0),
                d.get('network_bytes_recv', 0),
                d.get('network_connections', 0),
                d.get('network_entropy', 0),
                d.get('process_count', 0),
                d.get('disk_read_bytes', 0),
                d.get('disk_write_bytes', 0)
            ])
        return np.array(features)
```

---

## 7. Project Directory Structure

```
ProjectLibra/
├── src/
│   ├── __init__.py
│   ├── main.py                     # Application entry point
│   │
│   ├── collectors/                 # Data Collection Layer
│   │   ├── __init__.py
│   │   ├── base_collector.py
│   │   ├── log_collector.py
│   │   ├── process_collector.py
│   │   ├── network_collector.py
│   │   ├── metrics_collector.py
│   │   └── platform/
│   │       ├── linux_collector.py
│   │       ├── windows_collector.py
│   │       └── macos_collector.py
│   │
│   ├── database/                   # Dual Database System
│   │   ├── __init__.py
│   │   ├── dual_db_manager.py
│   │   ├── primary_db.py
│   │   ├── immutable_backup_db.py
│   │   └── integrity_validator.py
│   │
│   ├── agents/                     # Agentic AI Layer
│   │   ├── __init__.py
│   │   ├── base_agent.py
│   │   ├── observation_agent.py
│   │   ├── correlation_agent.py
│   │   ├── threat_reasoning_agent.py
│   │   ├── maintenance_agent.py
│   │   ├── learning_agent.py
│   │   └── orchestrator.py
│   │
│   ├── llm/                        # LLM Integration
│   │   ├── __init__.py
│   │   ├── llm_client.py
│   │   ├── openai_client.py
│   │   ├── ollama_client.py
│   │   ├── groq_client.py
│   │   └── gemini_client.py
│   │
│   ├── ml/                         # ML Behavioral Engine
│   │   ├── __init__.py
│   │   ├── behavioral_engine.py
│   │   ├── anomaly_detector.py
│   │   └── baseline_learner.py
│   │
│   ├── services/                   # Core Services
│   │   ├── __init__.py
│   │   ├── integrity_monitor.py
│   │   ├── alert_service.py
│   │   ├── patch_intelligence.py
│   │   └── event_processor.py
│   │
│   ├── api/                        # REST API
│   │   ├── __init__.py
│   │   ├── routes/
│   │   │   ├── events.py
│   │   │   ├── alerts.py
│   │   │   ├── integrity.py
│   │   │   └── config.py
│   │   └── server.py
│   │
│   ├── cli/                        # CLI Interface
│   │   ├── __init__.py
│   │   ├── main.py
│   │   └── commands/
│   │       ├── monitor.py
│   │       ├── analyze.py
│   │       └── report.py
│   │
│   └── web/                        # Web Dashboard
│       ├── static/
│       ├── templates/
│       └── app.py
│
├── config/
│   ├── default.yaml
│   ├── collectors.yaml
│   ├── llm.yaml
│   └── database.yaml
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
│
├── docs/
│   ├── architecture.md
│   ├── api.md
│   └── deployment.md
│
├── scripts/
│   ├── install.sh
│   ├── setup_db.sh
│   └── run_tests.sh
│
├── requirements.txt
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 8. Configuration Examples

### 8.1 Database Configuration

```yaml
# config/database.yaml
primary_database:
  type: sqlite  # Can be postgresql, mysql
  path: /var/lib/projectlibra/primary.db
  # For production PostgreSQL:
  # host: localhost
  # port: 5432
  # database: projectlibra_primary
  # user: app_user
  # password: ${PRIMARY_DB_PASSWORD}

backup_database:
  type: sqlite
  path: /var/lib/projectlibra/backup/immutable.db
  # For production - SEPARATE SERVER:
  # host: backup-server.internal
  # port: 5432
  # database: projectlibra_audit
  # user: audit_user  # INSERT ONLY permissions
  # password: ${BACKUP_DB_PASSWORD}
  
  # Security settings
  security:
    append_only: true
    require_hash_chain: true
    allow_delete: false
    allow_update: false

integrity_monitor:
  enabled: true
  check_interval_seconds: 300
  alert_on_tampering: true
  alert_channels:
    - email
    - slack
    - syslog
```

### 8.2 LLM Configuration

```yaml
# config/llm.yaml
default_provider: ollama  # Privacy-first, local by default

providers:
  ollama:
    enabled: true
    base_url: http://localhost:11434
    model: llama2:13b
    timeout: 60
    
  openai:
    enabled: false
    api_key: ${OPENAI_API_KEY}
    model: gpt-4
    max_tokens: 4096
    
  groq:
    enabled: false
    api_key: ${GROQ_API_KEY}
    model: mixtral-8x7b-32768

# Use local model for sensitive data, cloud for complex analysis
routing:
  sensitive_data: ollama
  complex_analysis: openai
  real_time: groq
```

---

## 9. Security Considerations

### 9.1 Backup Database Protection

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    BACKUP DATABASE SECURITY MEASURES                        │
│                                                                             │
│  1. NETWORK ISOLATION                                                       │
│     • Backup DB on separate network segment                                 │
│     • One-way data flow (write-only from main system)                      │
│     • No direct access from application servers                            │
│                                                                             │
│  2. ACCESS CONTROL                                                          │
│     • Separate credentials (not stored in main application)                │
│     • INSERT-only permissions (no UPDATE, DELETE)                          │
│     • No admin access from application                                      │
│                                                                             │
│  3. CRYPTOGRAPHIC INTEGRITY                                                 │
│     • Hash chain (blockchain-style)                                        │
│     • Digital signatures on records                                         │
│     • Periodic checksum verification                                        │
│                                                                             │
│  4. PHYSICAL SECURITY (for high-security deployments)                      │
│     • Air-gapped backup server                                             │
│     • Hardware security modules (HSM)                                       │
│     • Write-once storage media                                              │
│                                                                             │
│  5. MONITORING                                                              │
│     • Continuous integrity checks                                           │
│     • Alert on any anomalies                                                │
│     • Audit log of backup DB access                                         │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Deployment Options

### 10.1 Docker Compose (Development/Small Scale)

```yaml
# docker-compose.yml
version: '3.8'

services:
  projectlibra:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./data/primary:/var/lib/projectlibra/primary
      - ./config:/app/config
    environment:
      - LLM_PROVIDER=ollama
    depends_on:
      - ollama
      - backup-db
    networks:
      - app-network

  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama-data:/root/.ollama
    networks:
      - app-network

  # Backup database on ISOLATED network
  backup-db:
    image: postgres:15
    environment:
      POSTGRES_DB: projectlibra_audit
      POSTGRES_USER: audit_user
      POSTGRES_PASSWORD: ${BACKUP_DB_PASSWORD}
    volumes:
      - backup-db-data:/var/lib/postgresql/data
      - ./scripts/init-backup-db.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - backup-network  # SEPARATE network
    # No ports exposed - only accessible via internal network

  integrity-monitor:
    build: 
      context: .
      dockerfile: Dockerfile.monitor
    depends_on:
      - projectlibra
      - backup-db
    networks:
      - app-network
      - backup-network  # Has access to both for comparison

networks:
  app-network:
    driver: bridge
  backup-network:
    driver: bridge
    internal: true  # No external access

volumes:
  ollama-data:
  backup-db-data:
```

---

## 11. Summary

### Key Features:
1. **Cross-Platform Data Collection** - Linux, Windows, macOS support
2. **LLM-Powered Log Intelligence** - Semantic understanding of logs
3. **ML Behavioral Analysis** - Per-host baseline learning
4. **Agentic AI Architecture** - Multi-agent reasoning system
5. **Tamper-Proof Audit Logs** - Dual database with integrity verification
6. **Intelligent Patch Management** - Risk-aware update scheduling
7. **Multiple Interfaces** - CLI, Web Dashboard, API

### Security Guarantees:
- **Immutable backup database** - Attackers cannot modify audit logs
- **Hash chain integrity** - Any tampering is immediately detectable
- **Continuous monitoring** - Real-time detection of manipulation attempts
- **Separate credentials** - Compromising main DB doesn't compromise backup
- **Network isolation** - Backup DB protected from direct attack

This architecture ensures that even if an attacker gains full control of the primary system, the tamper-proof backup database maintains a verifiable record of all events, enabling forensic analysis and providing undeniable evidence of the attack.
