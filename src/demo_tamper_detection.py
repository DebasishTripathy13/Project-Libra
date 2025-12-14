"""
ProjectLibra - Demonstration of Dual Database Tamper Detection

This script demonstrates how the dual database system detects tampering.
"""

import asyncio
import os
import sys
import tempfile
from datetime import datetime
import uuid

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.dual_db_manager import DualDatabaseManager, create_dual_db_system
from services.integrity_monitor import IntegrityMonitorService


def print_section(title: str):
    """Print a formatted section header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


async def alert_handler(alert_data: dict):
    """Custom alert handler for demonstration"""
    print("\n🚨 ALERT RECEIVED BY CUSTOM HANDLER 🚨")
    print(f"  Alert Type: {alert_data['alert_type']}")
    print(f"  Severity: {alert_data['severity']}")
    print(f"  Tampered: {alert_data['tampered_count']}")
    print(f"  Missing: {alert_data['missing_count']}")


async def main():
    """Demonstrate the dual database tamper detection system"""
    
    print_section("ProjectLibra - Dual Database Tamper Detection Demo")
    
    # Create temporary directory for demo databases
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"\n📁 Using temporary directory: {tmpdir}")
        
        # Initialize the dual database system
        print_section("1. Initializing Dual Database System")
        db_manager = create_dual_db_system(tmpdir)
        print("✓ Primary database initialized")
        print("✓ Immutable backup database initialized")
        
        # Store some events
        print_section("2. Storing Sample Events")
        
        events = [
            {
                'event_id': f'evt-{uuid.uuid4().hex[:8]}',
                'event_type': 'login_success',
                'severity': 'info',
                'source': 'auth_system',
                'host_id': 'server-001',
                'raw_data': {'user': 'admin', 'ip': '192.168.1.100'},
                'normalized_data': {'action': 'user_login', 'outcome': 'success'}
            },
            {
                'event_id': f'evt-{uuid.uuid4().hex[:8]}',
                'event_type': 'process_start',
                'severity': 'info',
                'source': 'process_monitor',
                'host_id': 'server-001',
                'raw_data': {'process': 'nginx', 'pid': 1234},
                'normalized_data': {'action': 'process_start', 'service': 'web'}
            },
            {
                'event_id': f'evt-{uuid.uuid4().hex[:8]}',
                'event_type': 'suspicious_connection',
                'severity': 'warning',
                'source': 'network_monitor',
                'host_id': 'server-001',
                'raw_data': {'dest_ip': '10.0.0.99', 'port': 4444, 'bytes': 50000},
                'normalized_data': {'action': 'outbound_connection', 'risk': 'medium'}
            },
        ]
        
        stored_ids = []
        for event in events:
            success = db_manager.store_event(
                event_id=event['event_id'],
                timestamp=datetime.now(),
                source=event['source'],
                event_type=event['event_type'],
                severity=event['severity'],
                host_id=event['host_id'],
                raw_data=event['raw_data'],
                normalized_data=event['normalized_data']
            )
            stored_ids.append(event['event_id'])
            status = "✓" if success else "✗"
            print(f"  {status} Stored event: {event['event_id']} ({event['event_type']})")
        
        # Perform initial integrity check
        print_section("3. Initial Integrity Check (No Tampering)")
        report = db_manager.full_integrity_audit()
        print(f"  Status: {report.overall_status}")
        print(f"  Records checked: {report.total_records_checked}")
        print(f"  Valid: {report.valid_records}")
        print(f"  Tampered: {report.tampered_records}")
        print(f"  Missing: {report.missing_records}")
        print(f"  Hash chain valid: {report.chain_valid}")
        
        # Simulate attacker modifying a record
        print_section("4. Simulating Attacker: Modifying Record in Primary DB")
        target_id = stored_ids[2]  # The suspicious connection event
        print(f"  Target event: {target_id}")
        
        # Attacker modifies the event to hide suspicious activity
        db_manager.primary_db.update_event(target_id, {
            'severity': 'info',  # Changed from 'warning'
            'raw_data': {'dest_ip': '192.168.1.1', 'port': 80, 'bytes': 100}  # Sanitized
        })
        print("  ⚠ Attacker modified event severity and connection data")
        
        # Check integrity after modification
        print_section("5. Integrity Check After Modification")
        report = db_manager.full_integrity_audit()
        print(f"  Status: {report.overall_status}")
        print(f"  Tampered: {report.tampered_records}")
        
        if report.issues:
            print("\n  Issues detected:")
            for issue in report.issues:
                print(f"    🔴 [{issue['severity'].upper()}] {issue['message']}")
        
        # Simulate attacker deleting a record
        print_section("6. Simulating Attacker: Deleting Record from Primary DB")
        delete_target = stored_ids[0]  # The login event
        print(f"  Target event: {delete_target}")
        
        db_manager.primary_db.delete_event(delete_target)
        print("  ⚠ Attacker deleted login event to cover tracks")
        
        # Check integrity after deletion
        print_section("7. Integrity Check After Deletion")
        report = db_manager.full_integrity_audit()
        print(f"  Status: {report.overall_status}")
        print(f"  Tampered: {report.tampered_records}")
        print(f"  Missing: {report.missing_records}")
        
        if report.issues:
            print("\n  Issues detected:")
            for issue in report.issues:
                print(f"    🔴 [{issue['severity'].upper()}] {issue['message']}")
        
        # Get tampered records for forensics
        print_section("8. Forensic Analysis - Recovering Original Data")
        tampered = db_manager.get_tampered_records()
        
        for record in tampered:
            print(f"\n  Record: {record['record_id']}")
            print(f"  Issue Type: {record['issue_type']}")
            
            if record['issue_type'] == 'deleted_from_primary':
                print("  Status: DELETED from primary database")
                if record['backup_data']:
                    print("  Original data (preserved in backup):")
                    for key, value in record['backup_data'].items():
                        print(f"    {key}: {value}")
                        
            elif record['issue_type'] == 'content_modified':
                print("  Status: MODIFIED in primary database")
                if record['backup_data'] and record['primary_data']:
                    print("  \n  === COMPARISON ===")
                    print("  ORIGINAL (backup):                    MODIFIED (primary):")
                    print("  -----------------                     ------------------")
                    orig_raw = record['backup_data'].get('raw_data', {})
                    mod_raw = record['primary_data'].get('raw_data', {})
                    orig_severity = record['backup_data'].get('severity', 'N/A')
                    mod_severity = record['primary_data'].get('severity', 'N/A')
                    
                    print(f"  severity: {orig_severity:<28} severity: {mod_severity}")
                    print(f"  raw_data: {str(orig_raw):<28}")
                    print(f"  raw_data (modified): {str(mod_raw)}")
        
        # Verify hash chain
        print_section("9. Verifying Backup Hash Chain")
        chain_valid, broken_at = db_manager.backup_db.verify_chain_integrity()
        
        if chain_valid:
            print("  ✓ Hash chain is intact - backup database is trustworthy")
            print("  ✓ All backup records can be used as evidence")
        else:
            print(f"  ✗ Hash chain broken at sequence {broken_at}")
        
        # Run async integrity monitor briefly
        print_section("10. Running Real-time Integrity Monitor (5 seconds)")
        
        monitor = IntegrityMonitorService(
            db_manager,
            check_interval_seconds=2,
            alert_callback=alert_handler
        )
        
        # Run for 5 seconds
        async def run_monitor_briefly():
            task = asyncio.create_task(monitor.start())
            await asyncio.sleep(5)
            monitor.stop()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        
        await run_monitor_briefly()
        
        stats = monitor.get_stats()
        print(f"\n  Monitor stats:")
        print(f"    Checks performed: {stats['check_count']}")
        print(f"    Alerts raised: {stats['alert_count']}")
        
        # Summary
        print_section("SUMMARY")
        print("""
  The dual database system successfully detected:
  
  1. ✓ Record modification in primary database
  2. ✓ Record deletion from primary database
  3. ✓ Hash chain in backup remains intact
  4. ✓ Original data preserved in immutable backup
  5. ✓ Continuous monitoring with real-time alerts
  
  SECURITY BENEFITS:
  
  • Even with full access to primary DB, attackers cannot:
    - Modify records without detection
    - Delete records without detection
    - Forge historical entries
    
  • The backup database provides:
    - Tamper-proof audit trail
    - Cryptographic integrity verification
    - Evidence for forensic analysis
    - Proof of what really happened
        """)


if __name__ == '__main__':
    asyncio.run(main())
