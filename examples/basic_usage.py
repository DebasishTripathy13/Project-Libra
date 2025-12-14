#!/usr/bin/env python3
"""
ProjectLibra - Basic Usage Example

This script demonstrates the core functionality of the dual-database
tamper detection system.
"""

import sys
import os
import uuid
import sqlite3
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database.dual_db_manager import DualDatabaseManager


def main():
    """Demonstrate basic dual-database functionality."""
    print("=" * 60)
    print("ProjectLibra - Dual Database Tamper Detection Demo")
    print("=" * 60)
    
    # Initialize the dual database manager
    db_manager = DualDatabaseManager(
        primary_db_path="demo_primary.db",
        backup_db_path="demo_backup.db"
    )
    
    try:
        print("\n[1] Dual database system initialized")
        print("    ✓ Primary database ready")
        print("    ✓ Immutable backup database ready")
        
        # Insert some security events
        print("\n[2] Inserting security events...")
        events = [
            {
                "source": "auth_log",
                "event_type": "login_attempt",
                "severity": "info",
                "details": {"user": "admin", "ip": "192.168.1.100", "success": True}
            },
            {
                "source": "process_monitor",
                "event_type": "suspicious_process",
                "severity": "warning",
                "details": {"process": "unknown.exe", "pid": 1234, "parent": "cmd.exe"}
            },
            {
                "source": "network_monitor",
                "event_type": "outbound_connection",
                "severity": "critical",
                "details": {"dest_ip": "10.0.0.50", "dest_port": 4444, "protocol": "tcp"}
            }
        ]
        
        event_ids = []
        for event in events:
            event_id = str(uuid.uuid4())
            success = db_manager.store_event(
                event_id=event_id,
                timestamp=datetime.now(),
                source=event["source"],
                event_type=event["event_type"],
                severity=event["severity"],
                host_id="demo-host",
                raw_data=event["details"],
                normalized_data=event["details"]
            )
            event_ids.append(event_id)
            print(f"    ✓ Inserted event: {event['event_type']} (ID: {event_id[:8]}...)")
        
        # Verify integrity
        print("\n[3] Verifying database integrity...")
        integrity_report = db_manager.full_integrity_audit()
        print(f"    Total records: {integrity_report.total_records_checked}")
        print(f"    Valid records: {integrity_report.valid_records}")
        print(f"    Tampered: {integrity_report.tampered_records}")
        print(f"    Missing: {integrity_report.missing_records}")
        
        if integrity_report.valid_records == integrity_report.total_records_checked:
            print("    ✓ All records verified - no tampering detected")
        
        # Simulate an attack - modify primary database directly
        print("\n[4] Simulating attacker modifying primary database...")
        conn = sqlite3.connect("demo_primary.db")
        cursor = conn.cursor()
        # Attacker tries to change severity from 'critical' to 'info' to hide their tracks
        cursor.execute(
            "UPDATE events SET severity = 'info' WHERE event_id = ?",
            (event_ids[2],)
        )
        conn.commit()
        conn.close()
        print(f"    ⚠ Attacker modified severity of event ID {event_ids[2][:8]}...")
        
        # Verify integrity again - should detect tampering
        print("\n[5] Re-verifying integrity after attack...")
        integrity_report = db_manager.full_integrity_audit()
        print(f"    Total records: {integrity_report.total_records_checked}")
        print(f"    Valid records: {integrity_report.valid_records}")
        print(f"    Tampered: {integrity_report.tampered_records}")
        print(f"    Missing: {integrity_report.missing_records}")
        
        if integrity_report.tampered_records > 0:
            print("    🚨 TAMPERING DETECTED!")
            if integrity_report.issues:
                print("\n    Tampered records:")
                for issue in integrity_report.issues:
                    if issue.get('type') == 'content_modified':
                        print(f"      - Record ID: {issue.get('record_id', 'unknown')[:8]}...")
        
        # Simulate deletion attack
        print("\n[6] Simulating attacker deleting a record...")
        conn = sqlite3.connect("demo_primary.db")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM events WHERE event_id = ?", (event_ids[1],))
        conn.commit()
        conn.close()
        print(f"    ⚠ Attacker deleted event ID {event_ids[1][:8]}...")
        
        # Verify integrity - should detect missing record
        print("\n[7] Re-verifying integrity after deletion...")
        integrity_report = db_manager.full_integrity_audit()
        print(f"    Total records in backup: {integrity_report.total_records_checked}")
        print(f"    Valid records: {integrity_report.valid_records}")
        print(f"    Tampered: {integrity_report.tampered_records}")
        print(f"    Missing from primary: {integrity_report.missing_records}")
        
        if integrity_report.missing_records > 0:
            print("    🚨 DELETED RECORDS DETECTED!")
            if integrity_report.issues:
                print("\n    Missing record IDs:")
                for issue in integrity_report.issues:
                    if issue.get('type') == 'deleted_from_primary':
                        print(f"      - {issue.get('record_id', 'unknown')[:8]}...")
        
        print("\n" + "=" * 60)
        print("Demo Complete!")
        print("=" * 60)
        print("\nThe dual-database system successfully detected:")
        print("  • Record modification (hash mismatch)")
        print("  • Record deletion (missing from primary)")
        print("\nAttackers cannot cover their tracks without access to the")
        print("immutable backup database, which uses append-only triggers.")
        
    finally:
        # Cleanup demo files
        for f in ["demo_primary.db", "demo_backup.db"]:
            if os.path.exists(f):
                os.remove(f)
        print("\n[Cleanup] Demo database files removed.")


if __name__ == "__main__":
    main()
