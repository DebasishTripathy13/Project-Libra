"""
ProjectLibra - Dual Database Security System
Tamper-proof audit logging with integrity verification
"""

import hashlib
import json
import sqlite3
import threading
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class IntegrityStatus(Enum):
    """Status codes for integrity checks"""
    VALID = "valid"
    TAMPERED = "tampered"
    MISSING_PRIMARY = "missing_in_primary"
    MISSING_BACKUP = "missing_in_backup"
    HASH_MISMATCH = "hash_mismatch"
    CHAIN_BROKEN = "chain_broken"


@dataclass
class AuditRecord:
    """Single audit log entry with chain hash for tamper detection"""
    record_id: str
    timestamp: datetime
    event_type: str
    event_data: Dict[str, Any]
    content_hash: str           # Hash of the event data
    previous_hash: str          # Hash of previous record (blockchain-style)
    chain_hash: str             # Hash of (previous_hash + content_hash)
    sequence_number: int = 0


@dataclass
class IntegrityReport:
    """Report from integrity check"""
    check_timestamp: datetime
    total_records_checked: int
    valid_records: int
    tampered_records: int
    missing_records: int
    chain_valid: bool
    issues: List[Dict[str, Any]] = field(default_factory=list)
    overall_status: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'check_timestamp': self.check_timestamp.isoformat(),
            'total_records_checked': self.total_records_checked,
            'valid_records': self.valid_records,
            'tampered_records': self.tampered_records,
            'missing_records': self.missing_records,
            'chain_valid': self.chain_valid,
            'issues': self.issues,
            'overall_status': self.overall_status
        }


class ImmutableBackupDB:
    """
    Immutable backup database with:
    - Append-only operations (no UPDATE, DELETE)
    - Cryptographic hash chains (blockchain-style)
    - Separate credentials from main database
    - Write-Once Read-Many (WORM) semantics
    
    This database serves as the tamper-proof source of truth.
    Even if an attacker compromises the main database, they cannot
    modify this backup without breaking the hash chain.
    """
    
    GENESIS_SEED = b"PROJECTLIBRA_GENESIS_BLOCK_v1"
    
    def __init__(self, db_path: str, credentials: Optional[Dict[str, str]] = None):
        """
        Initialize the immutable backup database.
        
        Args:
            db_path: Path to SQLite database file
            credentials: Optional credentials dict (for future PostgreSQL support)
        """
        self.db_path = db_path
        self.credentials = credentials or {}
        self._lock = threading.Lock()
        self._last_chain_hash = self._get_genesis_hash()
        self._sequence_counter = 0
        self._init_db()
    
    def _get_genesis_hash(self) -> str:
        """Generate the genesis block hash for the chain"""
        return hashlib.sha256(self.GENESIS_SEED).hexdigest()
    
    def _init_db(self):
        """Initialize database with restricted schema and triggers"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create immutable audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT UNIQUE NOT NULL,
                sequence_number INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                chain_hash TEXT NOT NULL,
                inserted_at TEXT DEFAULT CURRENT_TIMESTAMP,
                
                -- Ensure sequence is strictly increasing
                CONSTRAINT seq_check CHECK (sequence_number >= 0)
            )
        ''')
        
        # Create indexes for fast lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_audit_record_id 
            ON audit_log(record_id)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
            ON audit_log(timestamp)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_audit_sequence 
            ON audit_log(sequence_number)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_audit_event_type 
            ON audit_log(event_type)
        ''')
        
        # CRITICAL: Create triggers to PREVENT updates and deletes
        # This enforces WORM (Write Once Read Many) semantics
        cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS prevent_audit_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 
                    'SECURITY VIOLATION: Updates are forbidden on immutable audit log');
            END
        ''')
        
        cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 
                    'SECURITY VIOLATION: Deletes are forbidden on immutable audit log');
            END
        ''')
        
        # Create metadata table for chain state
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chain_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Load the last chain state
        self._load_chain_state()
    
    def _load_chain_state(self):
        """Load the most recent chain hash and sequence for continuity"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT chain_hash, sequence_number 
            FROM audit_log 
            ORDER BY sequence_number DESC 
            LIMIT 1
        ''')
        result = cursor.fetchone()
        conn.close()
        
        if result:
            self._last_chain_hash = result[0]
            self._sequence_counter = result[1]
        else:
            self._last_chain_hash = self._get_genesis_hash()
            self._sequence_counter = 0
    
    def _compute_content_hash(self, event_data: Dict[str, Any]) -> str:
        """Compute SHA-256 hash of event content"""
        # Serialize with sorted keys for deterministic hashing
        content = json.dumps(event_data, sort_keys=True, default=str)
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def _compute_chain_hash(self, previous_hash: str, content_hash: str) -> str:
        """
        Compute chain hash linking to previous record.
        This creates a blockchain-style integrity chain.
        """
        combined = f"{previous_hash}:{content_hash}"
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()
    
    def append_record(self, 
                      record_id: str, 
                      event_type: str, 
                      event_data: Dict[str, Any], 
                      timestamp: Optional[datetime] = None) -> AuditRecord:
        """
        Append a new record to the immutable log.
        This is the ONLY write operation allowed.
        
        Args:
            record_id: Unique identifier for this record
            event_type: Type of event being logged
            event_data: Dictionary containing event details
            timestamp: Event timestamp (defaults to now)
            
        Returns:
            AuditRecord with computed hashes
            
        Raises:
            sqlite3.IntegrityError: If record_id already exists
        """
        timestamp = timestamp or datetime.now()
        
        with self._lock:
            content_hash = self._compute_content_hash(event_data)
            previous_hash = self._last_chain_hash
            chain_hash = self._compute_chain_hash(previous_hash, content_hash)
            self._sequence_counter += 1
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    INSERT INTO audit_log 
                    (record_id, sequence_number, timestamp, event_type, 
                     event_data, content_hash, previous_hash, chain_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    record_id,
                    self._sequence_counter,
                    timestamp.isoformat(),
                    event_type,
                    json.dumps(event_data, default=str),
                    content_hash,
                    previous_hash,
                    chain_hash
                ))
                conn.commit()
                
                # Update chain state
                self._last_chain_hash = chain_hash
                
                logger.info(f"Appended audit record: {record_id} (seq: {self._sequence_counter})")
                
                return AuditRecord(
                    record_id=record_id,
                    timestamp=timestamp,
                    event_type=event_type,
                    event_data=event_data,
                    content_hash=content_hash,
                    previous_hash=previous_hash,
                    chain_hash=chain_hash,
                    sequence_number=self._sequence_counter
                )
            except sqlite3.IntegrityError as e:
                self._sequence_counter -= 1  # Rollback counter
                logger.error(f"Failed to append record {record_id}: {e}")
                raise
            finally:
                conn.close()
    
    def verify_chain_integrity(self) -> tuple[bool, Optional[int]]:
        """
        Verify the entire hash chain is intact.
        
        Returns:
            Tuple of (is_valid, first_broken_sequence)
            If valid, second element is None.
            If broken, second element is the sequence number where chain breaks.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT sequence_number, content_hash, previous_hash, chain_hash 
            FROM audit_log 
            ORDER BY sequence_number ASC
        ''')
        
        expected_previous = self._get_genesis_hash()
        
        for row in cursor.fetchall():
            seq, content_hash, previous_hash, chain_hash = row
            
            # Verify previous hash links correctly
            if previous_hash != expected_previous:
                conn.close()
                logger.warning(f"Chain broken at sequence {seq}: previous_hash mismatch")
                return False, seq
            
            # Verify chain hash is correct
            expected_chain = self._compute_chain_hash(previous_hash, content_hash)
            if chain_hash != expected_chain:
                conn.close()
                logger.warning(f"Chain broken at sequence {seq}: chain_hash mismatch")
                return False, seq
            
            expected_previous = chain_hash
        
        conn.close()
        return True, None
    
    def get_record(self, record_id: str) -> Optional[AuditRecord]:
        """Retrieve a specific record by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT record_id, sequence_number, timestamp, event_type, 
                   event_data, content_hash, previous_hash, chain_hash
            FROM audit_log 
            WHERE record_id = ?
        ''', (record_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return AuditRecord(
                record_id=row[0],
                sequence_number=row[1],
                timestamp=datetime.fromisoformat(row[2]),
                event_type=row[3],
                event_data=json.loads(row[4]),
                content_hash=row[5],
                previous_hash=row[6],
                chain_hash=row[7]
            )
        return None
    
    def get_records_in_range(self, 
                             start_time: datetime, 
                             end_time: datetime) -> List[AuditRecord]:
        """Retrieve all records within a time range"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT record_id, sequence_number, timestamp, event_type,
                   event_data, content_hash, previous_hash, chain_hash
            FROM audit_log
            WHERE timestamp BETWEEN ? AND ?
            ORDER BY sequence_number ASC
        ''', (start_time.isoformat(), end_time.isoformat()))
        
        records = []
        for row in cursor.fetchall():
            records.append(AuditRecord(
                record_id=row[0],
                sequence_number=row[1],
                timestamp=datetime.fromisoformat(row[2]),
                event_type=row[3],
                event_data=json.loads(row[4]),
                content_hash=row[5],
                previous_hash=row[6],
                chain_hash=row[7]
            ))
        
        conn.close()
        return records
    
    def get_all_record_ids(self) -> List[str]:
        """Get all record IDs in the backup"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT record_id FROM audit_log ORDER BY sequence_number')
        ids = [row[0] for row in cursor.fetchall()]
        conn.close()
        return ids
    
    def get_record_count(self) -> int:
        """Get total number of records"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM audit_log')
        count = cursor.fetchone()[0]
        conn.close()
        return count


class PrimaryDB:
    """
    Primary database for normal operations.
    Full CRUD operations allowed.
    
    This is the database that the application uses day-to-day.
    It may be subject to tampering if an attacker gains access.
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize primary database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main events table
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
        
        # Behavioral baselines table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS behavioral_baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id TEXT NOT NULL,
                metric_type TEXT NOT NULL,
                baseline_data TEXT NOT NULL,
                model_data BLOB,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(host_id, metric_type)
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                event_ids TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT DEFAULT 'open',
                assigned_to TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                resolved_at TEXT
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_host ON events(host_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')
        
        conn.commit()
        conn.close()
    
    def insert_event(self, event_id: str, timestamp: datetime, source: str,
                     event_type: str, severity: str, host_id: str,
                     raw_data: Dict, normalized_data: Dict, 
                     content_hash: str) -> bool:
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
                event_id,
                timestamp.isoformat(),
                source,
                event_type,
                severity,
                host_id,
                json.dumps(raw_data),
                json.dumps(normalized_data),
                content_hash
            ))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            logger.warning(f"Event {event_id} already exists")
            return False
        except Exception as e:
            logger.error(f"Error inserting event: {e}")
            return False
        finally:
            conn.close()
    
    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an event by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT event_id, timestamp, source, event_type, severity,
                   host_id, raw_data, normalized_data, content_hash
            FROM events 
            WHERE event_id = ?
        ''', (event_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'event_id': row[0],
                'timestamp': row[1],
                'source': row[2],
                'event_type': row[3],
                'severity': row[4],
                'host_id': row[5],
                'raw_data': json.loads(row[6]),
                'normalized_data': json.loads(row[7]),
                'content_hash': row[8]
            }
        return None
    
    def get_all_event_ids(self) -> List[str]:
        """Get all event IDs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT event_id FROM events ORDER BY timestamp')
        ids = [row[0] for row in cursor.fetchall()]
        conn.close()
        return ids
    
    def delete_event(self, event_id: str) -> bool:
        """Delete an event (attackers might try this)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM events WHERE event_id = ?', (event_id,))
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted
    
    def update_event(self, event_id: str, updates: Dict[str, Any]) -> bool:
        """Update an event (attackers might try this)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Build update query
        set_clauses = []
        values = []
        for key, value in updates.items():
            if key in ['raw_data', 'normalized_data']:
                value = json.dumps(value)
            set_clauses.append(f"{key} = ?")
            values.append(value)
        
        values.append(event_id)
        query = f"UPDATE events SET {', '.join(set_clauses)}, updated_at = CURRENT_TIMESTAMP WHERE event_id = ?"
        
        cursor.execute(query, values)
        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated


class DualDatabaseManager:
    """
    Manager that coordinates writes to both databases
    and performs integrity validation.
    
    SECURITY MODEL:
    - All events are written to BOTH databases
    - Primary DB can be modified (by app or attacker)
    - Backup DB is append-only with hash chain
    - Integrity checks compare the two to detect tampering
    """
    
    def __init__(self,
                 primary_db_path: str,
                 backup_db_path: str,
                 backup_credentials: Optional[Dict[str, str]] = None):
        """
        Initialize dual database manager.
        
        Args:
            primary_db_path: Path to primary database
            backup_db_path: Path to backup database (should be on separate storage/server)
            backup_credentials: Credentials for backup DB (different from main app)
        """
        self.primary_db = PrimaryDB(primary_db_path)
        self.backup_db = ImmutableBackupDB(backup_db_path, backup_credentials)
        
        logger.info("DualDatabaseManager initialized")
        logger.info(f"  Primary DB: {primary_db_path}")
        logger.info(f"  Backup DB: {backup_db_path}")
    
    def store_event(self,
                    event_id: str,
                    timestamp: datetime,
                    source: str,
                    event_type: str,
                    severity: str,
                    host_id: str,
                    raw_data: Dict[str, Any],
                    normalized_data: Dict[str, Any]) -> bool:
        """
        Store event in BOTH databases.
        
        Returns True only if both writes succeed.
        """
        # Compute content hash - includes ALL critical fields
        content = json.dumps({
            'event_id': event_id,
            'timestamp': timestamp.isoformat(),
            'source': source,
            'event_type': event_type,
            'severity': severity,
            'host_id': host_id,
            'raw_data': raw_data
        }, sort_keys=True)
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        # Write to primary
        primary_success = self.primary_db.insert_event(
            event_id=event_id,
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            severity=severity,
            host_id=host_id,
            raw_data=raw_data,
            normalized_data=normalized_data,
            content_hash=content_hash
        )
        
        # Write to backup (append-only)
        try:
            self.backup_db.append_record(
                record_id=event_id,
                event_type=event_type,
                event_data={
                    'source': source,
                    'severity': severity,
                    'host_id': host_id,
                    'raw_data': raw_data,
                    'content_hash': content_hash
                },
                timestamp=timestamp
            )
            backup_success = True
        except Exception as e:
            logger.error(f"Backup write failed: {e}")
            backup_success = False
        
        return primary_success and backup_success
    
    def check_single_record_integrity(self, event_id: str) -> IntegrityStatus:
        """
        Check if a specific event has been tampered with.
        
        Compares the event in primary DB with the backup.
        Key: We RECOMPUTE the hash from primary data and compare to backup.
        This detects modifications even if attacker doesn't update the stored hash.
        """
        primary_event = self.primary_db.get_event(event_id)
        backup_record = self.backup_db.get_record(event_id)
        
        # Both don't exist - OK
        if not primary_event and not backup_record:
            return IntegrityStatus.VALID
        
        # Deleted from primary but exists in backup - TAMPERED
        if not primary_event and backup_record:
            logger.warning(f"TAMPERING DETECTED: Record {event_id} deleted from primary")
            return IntegrityStatus.MISSING_PRIMARY
        
        # Exists in primary but not backup - Error (should never happen)
        if primary_event and not backup_record:
            logger.error(f"Record {event_id} missing from backup - data integrity error")
            return IntegrityStatus.MISSING_BACKUP
        
        # Both exist - RECOMPUTE hash from current primary data and compare to backup
        # This catches modifications even if attacker left the stored hash unchanged
        current_content = json.dumps({
            'event_id': primary_event['event_id'],
            'timestamp': primary_event['timestamp'],
            'source': primary_event['source'],
            'event_type': primary_event['event_type'],
            'severity': primary_event['severity'],
            'host_id': primary_event['host_id'],
            'raw_data': primary_event['raw_data']
        }, sort_keys=True)
        current_hash = hashlib.sha256(current_content.encode()).hexdigest()
        
        # Compare recomputed hash with the original hash stored in backup
        if current_hash != backup_record.event_data['content_hash']:
            logger.warning(f"TAMPERING DETECTED: Record {event_id} content modified")
            return IntegrityStatus.HASH_MISMATCH
        
        return IntegrityStatus.VALID
    
    def full_integrity_audit(self) -> IntegrityReport:
        """
        Perform a comprehensive integrity audit.
        
        1. Verify backup chain integrity
        2. Compare all records between primary and backup
        3. Report any discrepancies
        """
        report = IntegrityReport(
            check_timestamp=datetime.now(),
            total_records_checked=0,
            valid_records=0,
            tampered_records=0,
            missing_records=0,
            chain_valid=True
        )
        
        # Step 1: Verify backup chain integrity
        chain_valid, broken_at = self.backup_db.verify_chain_integrity()
        report.chain_valid = chain_valid
        
        if not chain_valid:
            report.overall_status = "CRITICAL: Backup chain compromised"
            report.issues.append({
                'type': 'chain_integrity_failure',
                'sequence': broken_at,
                'severity': 'critical',
                'message': f'Hash chain broken at sequence {broken_at}'
            })
            return report
        
        # Step 2: Get all records from backup (source of truth)
        backup_ids = set(self.backup_db.get_all_record_ids())
        primary_ids = set(self.primary_db.get_all_event_ids())
        
        # Check for records in backup but not in primary (deleted)
        deleted_ids = backup_ids - primary_ids
        for record_id in deleted_ids:
            report.missing_records += 1
            report.issues.append({
                'type': 'deleted_from_primary',
                'record_id': record_id,
                'severity': 'high',
                'message': f'Record {record_id} was deleted from primary database'
            })
        
        # Check for records in primary but not in backup (shouldn't happen)
        orphan_ids = primary_ids - backup_ids
        for record_id in orphan_ids:
            report.issues.append({
                'type': 'missing_from_backup',
                'record_id': record_id,
                'severity': 'medium',
                'message': f'Record {record_id} exists in primary but not backup'
            })
        
        # Check content integrity for common records
        common_ids = backup_ids & primary_ids
        for record_id in common_ids:
            report.total_records_checked += 1
            status = self.check_single_record_integrity(record_id)
            
            if status == IntegrityStatus.VALID:
                report.valid_records += 1
            elif status == IntegrityStatus.HASH_MISMATCH:
                report.tampered_records += 1
                report.issues.append({
                    'type': 'content_modified',
                    'record_id': record_id,
                    'severity': 'critical',
                    'message': f'Record {record_id} content was modified in primary'
                })
        
        # Set overall status
        if report.tampered_records > 0 or report.missing_records > 0:
            report.overall_status = "ALERT: Tampering Detected"
        elif len(report.issues) > 0:
            report.overall_status = "WARNING: Issues Found"
        else:
            report.overall_status = "OK: All records verified"
        
        logger.info(f"Integrity audit complete: {report.overall_status}")
        logger.info(f"  Checked: {report.total_records_checked}")
        logger.info(f"  Valid: {report.valid_records}")
        logger.info(f"  Tampered: {report.tampered_records}")
        logger.info(f"  Missing: {report.missing_records}")
        
        return report
    
    def get_tampered_records(self) -> List[Dict[str, Any]]:
        """
        Get list of all tampered/deleted records with details.
        Useful for forensic analysis.
        """
        report = self.full_integrity_audit()
        tampered = []
        
        for issue in report.issues:
            if issue['type'] in ['deleted_from_primary', 'content_modified']:
                record_id = issue['record_id']
                backup_record = self.backup_db.get_record(record_id)
                primary_record = self.primary_db.get_event(record_id)
                
                tampered.append({
                    'record_id': record_id,
                    'issue_type': issue['type'],
                    'backup_data': backup_record.event_data if backup_record else None,
                    'primary_data': primary_record if primary_record else None,
                    'backup_timestamp': backup_record.timestamp.isoformat() if backup_record else None
                })
        
        return tampered


# Convenience function for quick setup
def create_dual_db_system(data_dir: str) -> DualDatabaseManager:
    """
    Create a dual database system with default paths.
    
    In production, backup DB should be on a separate server/storage.
    """
    import os
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(os.path.join(data_dir, 'backup'), exist_ok=True)
    
    primary_path = os.path.join(data_dir, 'primary.db')
    backup_path = os.path.join(data_dir, 'backup', 'immutable.db')
    
    return DualDatabaseManager(
        primary_db_path=primary_path,
        backup_db_path=backup_path
    )
