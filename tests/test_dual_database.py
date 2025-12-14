"""
Tests for the dual database tamper detection system.
"""

import pytest
import asyncio
import sqlite3
import os
import json
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database.dual_db_manager import (
    DualDatabaseManager,
    ImmutableBackupDB,
    PrimaryDB
)


@pytest.fixture
def db_paths(tmp_path):
    """Create temporary database paths for testing."""
    return {
        "primary": str(tmp_path / "test_primary.db"),
        "backup": str(tmp_path / "test_backup.db")
    }


@pytest.fixture
async def db_manager(db_paths):
    """Create and initialize a database manager for testing."""
    manager = DualDatabaseManager(
        primary_db_path=db_paths["primary"],
        backup_db_path=db_paths["backup"]
    )
    await manager.initialize()
    yield manager
    await manager.close()


class TestDualDatabaseManager:
    """Tests for DualDatabaseManager."""
    
    @pytest.mark.asyncio
    async def test_initialize_creates_databases(self, db_paths):
        """Test that initialization creates both databases."""
        manager = DualDatabaseManager(
            primary_db_path=db_paths["primary"],
            backup_db_path=db_paths["backup"]
        )
        await manager.initialize()
        
        assert os.path.exists(db_paths["primary"])
        assert os.path.exists(db_paths["backup"])
        
        await manager.close()
    
    @pytest.mark.asyncio
    async def test_insert_event_returns_id(self, db_manager):
        """Test that inserting an event returns a valid ID."""
        record_id = await db_manager.insert_event(
            source="test",
            event_type="test_event",
            severity="info",
            details={"key": "value"}
        )
        
        assert record_id is not None
        assert record_id > 0
    
    @pytest.mark.asyncio
    async def test_insert_event_syncs_to_both_databases(self, db_manager, db_paths):
        """Test that events are written to both databases."""
        record_id = await db_manager.insert_event(
            source="test",
            event_type="sync_test",
            severity="warning",
            details={"test": True}
        )
        
        # Check primary database
        conn = sqlite3.connect(db_paths["primary"])
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs WHERE id = ?", (record_id,))
        primary_record = cursor.fetchone()
        conn.close()
        
        # Check backup database
        conn = sqlite3.connect(db_paths["backup"])
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM immutable_logs WHERE id = ?", (record_id,))
        backup_record = cursor.fetchone()
        conn.close()
        
        assert primary_record is not None
        assert backup_record is not None
    
    @pytest.mark.asyncio
    async def test_integrity_check_passes_for_unmodified_data(self, db_manager):
        """Test that integrity check passes when data is not tampered."""
        # Insert several events
        for i in range(5):
            await db_manager.insert_event(
                source="test",
                event_type=f"event_{i}",
                severity="info",
                details={"index": i}
            )
        
        # Verify integrity
        results = await db_manager.verify_integrity()
        
        assert results["total"] == 5
        assert results["valid"] == 5
        assert results["tampered"] == 0
        assert results["missing"] == 0
    
    @pytest.mark.asyncio
    async def test_detects_modified_record(self, db_manager, db_paths):
        """Test that tampering with a record is detected."""
        # Insert an event
        record_id = await db_manager.insert_event(
            source="sensitive",
            event_type="critical_event",
            severity="critical",
            details={"data": "original"}
        )
        
        # Tamper with the primary database directly
        conn = sqlite3.connect(db_paths["primary"])
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE audit_logs SET severity = 'info' WHERE id = ?",
            (record_id,)
        )
        conn.commit()
        conn.close()
        
        # Verify integrity - should detect tampering
        results = await db_manager.verify_integrity()
        
        assert results["tampered"] == 1
        assert record_id in [r["id"] for r in results["tampered_records"]]
    
    @pytest.mark.asyncio
    async def test_detects_deleted_record(self, db_manager, db_paths):
        """Test that deleting a record is detected."""
        # Insert events
        record_id = await db_manager.insert_event(
            source="test",
            event_type="to_delete",
            severity="warning",
            details={}
        )
        
        # Delete from primary database
        conn = sqlite3.connect(db_paths["primary"])
        cursor = conn.cursor()
        cursor.execute("DELETE FROM audit_logs WHERE id = ?", (record_id,))
        conn.commit()
        conn.close()
        
        # Verify integrity - should detect missing record
        results = await db_manager.verify_integrity()
        
        assert results["missing"] == 1
        assert record_id in results["missing_records"]
    
    @pytest.mark.asyncio
    async def test_hash_chain_integrity(self, db_manager, db_paths):
        """Test that hash chain maintains integrity."""
        # Insert multiple events
        ids = []
        for i in range(3):
            record_id = await db_manager.insert_event(
                source="chain_test",
                event_type=f"event_{i}",
                severity="info",
                details={"seq": i}
            )
            ids.append(record_id)
        
        # Verify each record's hash chain
        conn = sqlite3.connect(db_paths["backup"])
        cursor = conn.cursor()
        
        prev_hash = None
        for record_id in ids:
            cursor.execute(
                "SELECT previous_hash, record_hash FROM immutable_logs WHERE id = ?",
                (record_id,)
            )
            row = cursor.fetchone()
            
            if prev_hash is not None:
                assert row[0] == prev_hash, "Hash chain broken"
            
            prev_hash = row[1]
        
        conn.close()


class TestImmutableBackupDB:
    """Tests for the immutable backup database."""
    
    @pytest.mark.asyncio
    async def test_delete_trigger_prevents_deletion(self, db_paths):
        """Test that the DELETE trigger prevents record deletion."""
        backup_db = ImmutableBackupDB(db_paths["backup"])
        await backup_db.initialize()
        
        # Insert a record
        record_id = await backup_db.insert_record(
            record_id=1,
            source="test",
            event_type="test",
            severity="info",
            details=json.dumps({}),
            previous_hash="",
            record_hash="abc123"
        )
        
        # Try to delete - should fail due to trigger
        conn = sqlite3.connect(db_paths["backup"])
        cursor = conn.cursor()
        
        with pytest.raises(sqlite3.IntegrityError):
            cursor.execute("DELETE FROM immutable_logs WHERE id = ?", (record_id,))
        
        conn.close()
        await backup_db.close()
    
    @pytest.mark.asyncio
    async def test_update_trigger_prevents_modification(self, db_paths):
        """Test that the UPDATE trigger prevents record modification."""
        backup_db = ImmutableBackupDB(db_paths["backup"])
        await backup_db.initialize()
        
        # Insert a record
        await backup_db.insert_record(
            record_id=1,
            source="test",
            event_type="test",
            severity="critical",
            details=json.dumps({}),
            previous_hash="",
            record_hash="abc123"
        )
        
        # Try to update - should fail due to trigger
        conn = sqlite3.connect(db_paths["backup"])
        cursor = conn.cursor()
        
        with pytest.raises(sqlite3.IntegrityError):
            cursor.execute(
                "UPDATE immutable_logs SET severity = 'info' WHERE id = 1"
            )
        
        conn.close()
        await backup_db.close()


class TestPrimaryDB:
    """Tests for the primary operational database."""
    
    @pytest.mark.asyncio
    async def test_crud_operations(self, db_paths):
        """Test basic CRUD operations on primary database."""
        primary_db = PrimaryDB(db_paths["primary"])
        await primary_db.initialize()
        
        # Create
        record_id = await primary_db.insert_record(
            source="crud_test",
            event_type="create",
            severity="info",
            details=json.dumps({"action": "create"})
        )
        assert record_id > 0
        
        # Read
        record = await primary_db.get_record(record_id)
        assert record is not None
        assert record["source"] == "crud_test"
        
        # Update (primary allows updates)
        conn = sqlite3.connect(db_paths["primary"])
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE audit_logs SET severity = 'warning' WHERE id = ?",
            (record_id,)
        )
        conn.commit()
        conn.close()
        
        # Verify update
        record = await primary_db.get_record(record_id)
        assert record["severity"] == "warning"
        
        await primary_db.close()
    
    @pytest.mark.asyncio
    async def test_query_by_severity(self, db_paths):
        """Test querying records by severity level."""
        primary_db = PrimaryDB(db_paths["primary"])
        await primary_db.initialize()
        
        # Insert records with different severities
        for severity in ["info", "warning", "critical", "info"]:
            await primary_db.insert_record(
                source="severity_test",
                event_type="test",
                severity=severity,
                details=json.dumps({})
            )
        
        # Query critical events
        critical_events = await primary_db.query_by_severity("critical")
        assert len(critical_events) == 1
        
        # Query info events
        info_events = await primary_db.query_by_severity("info")
        assert len(info_events) == 2
        
        await primary_db.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
