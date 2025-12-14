"""
ProjectLibra - Integrity Monitor Service
Continuous monitoring for database tampering detection
"""

import asyncio
import logging
from datetime import datetime
from typing import Callable, Optional, List, Dict, Any
from dataclasses import dataclass
import json
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.dual_db_manager import DualDatabaseManager, IntegrityReport, IntegrityStatus

logger = logging.getLogger(__name__)


@dataclass
class TamperingAlert:
    """Alert raised when tampering is detected"""
    alert_id: str
    alert_type: str
    severity: str
    timestamp: datetime
    tampered_count: int
    missing_count: int
    chain_compromised: bool
    issues: List[Dict[str, Any]]
    recommended_actions: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'alert_id': self.alert_id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat(),
            'tampered_count': self.tampered_count,
            'missing_count': self.missing_count,
            'chain_compromised': self.chain_compromised,
            'issues': self.issues,
            'recommended_actions': self.recommended_actions
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class IntegrityMonitorService:
    """
    Continuous monitoring service that:
    1. Periodically checks database integrity
    2. Detects tampering by comparing primary and backup databases
    3. Raises alerts when manipulation is detected
    4. Provides real-time tamper notifications
    
    SECURITY DESIGN:
    - Runs independently of main application
    - Can be deployed on a separate monitoring server
    - Alerts immediately when discrepancies are found
    - Maintains its own log of integrity checks
    """
    
    DEFAULT_CHECK_INTERVAL = 300  # 5 minutes
    
    def __init__(self,
                 dual_db_manager: DualDatabaseManager,
                 check_interval_seconds: int = DEFAULT_CHECK_INTERVAL,
                 alert_callback: Optional[Callable] = None,
                 alert_channels: Optional[List[str]] = None):
        """
        Initialize the integrity monitor.
        
        Args:
            dual_db_manager: The dual database manager to monitor
            check_interval_seconds: How often to check (default 5 minutes)
            alert_callback: Async function to call when tampering detected
            alert_channels: List of alert channels ('email', 'slack', 'syslog', etc.)
        """
        self.db_manager = dual_db_manager
        self.check_interval = check_interval_seconds
        self.alert_callback = alert_callback
        self.alert_channels = alert_channels or ['log']
        
        self._running = False
        self._last_report: Optional[IntegrityReport] = None
        self._check_count = 0
        self._alert_count = 0
        self._start_time: Optional[datetime] = None
        
        logger.info(f"IntegrityMonitorService initialized (interval: {check_interval_seconds}s)")
    
    async def start(self):
        """Start the integrity monitoring loop"""
        self._running = True
        self._start_time = datetime.now()
        logger.info("=" * 60)
        logger.info("INTEGRITY MONITOR SERVICE STARTED")
        logger.info(f"Check interval: {self.check_interval} seconds")
        logger.info(f"Alert channels: {self.alert_channels}")
        logger.info("=" * 60)
        
        while self._running:
            try:
                await self._perform_check()
                await asyncio.sleep(self.check_interval)
            except asyncio.CancelledError:
                logger.info("Monitor service cancelled")
                break
            except Exception as e:
                logger.error(f"Integrity check error: {e}", exc_info=True)
                await asyncio.sleep(60)  # Wait before retry
    
    async def _perform_check(self):
        """Perform a single integrity check"""
        self._check_count += 1
        check_start = datetime.now()
        
        logger.info(f"[Check #{self._check_count}] Starting integrity audit...")
        
        # Perform the audit
        report = self.db_manager.full_integrity_audit()
        self._last_report = report
        
        check_duration = (datetime.now() - check_start).total_seconds()
        
        # Log results
        self._log_check_results(report, check_duration)
        
        # Raise alert if tampering detected
        if self._should_alert(report):
            await self._raise_tampering_alert(report)
    
    def _log_check_results(self, report: IntegrityReport, duration: float):
        """Log the results of an integrity check"""
        status_emoji = "✓" if report.overall_status.startswith("OK") else "⚠"
        
        logger.info(f"[Check #{self._check_count}] {status_emoji} {report.overall_status}")
        logger.info(f"  Duration: {duration:.2f}s")
        logger.info(f"  Records checked: {report.total_records_checked}")
        logger.info(f"  Valid: {report.valid_records}")
        logger.info(f"  Tampered: {report.tampered_records}")
        logger.info(f"  Missing: {report.missing_records}")
        logger.info(f"  Chain valid: {report.chain_valid}")
        
        if report.issues:
            logger.warning(f"  Issues found: {len(report.issues)}")
            for issue in report.issues[:5]:  # Show first 5
                logger.warning(f"    - [{issue['severity']}] {issue['message']}")
            if len(report.issues) > 5:
                logger.warning(f"    ... and {len(report.issues) - 5} more issues")
    
    def _should_alert(self, report: IntegrityReport) -> bool:
        """Determine if an alert should be raised"""
        return (
            report.tampered_records > 0 or
            report.missing_records > 0 or
            not report.chain_valid
        )
    
    async def _raise_tampering_alert(self, report: IntegrityReport):
        """Raise a high-priority tampering alert"""
        self._alert_count += 1
        
        alert = TamperingAlert(
            alert_id=f"TAMP-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self._alert_count}",
            alert_type='DATABASE_TAMPERING_DETECTED',
            severity='CRITICAL' if not report.chain_valid else 'HIGH',
            timestamp=datetime.now(),
            tampered_count=report.tampered_records,
            missing_count=report.missing_records,
            chain_compromised=not report.chain_valid,
            issues=report.issues,
            recommended_actions=self._get_recommended_actions(report)
        )
        
        # Log the alert
        logger.critical("=" * 60)
        logger.critical("🚨 TAMPERING ALERT 🚨")
        logger.critical("=" * 60)
        logger.critical(f"Alert ID: {alert.alert_id}")
        logger.critical(f"Severity: {alert.severity}")
        logger.critical(f"Tampered records: {alert.tampered_count}")
        logger.critical(f"Deleted records: {alert.missing_count}")
        logger.critical(f"Chain compromised: {alert.chain_compromised}")
        logger.critical("Recommended actions:")
        for action in alert.recommended_actions:
            logger.critical(f"  • {action}")
        logger.critical("=" * 60)
        
        # Send through alert channels
        await self._send_alerts(alert)
        
        # Call custom callback if provided
        if self.alert_callback:
            try:
                await self.alert_callback(alert.to_dict())
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")
    
    def _get_recommended_actions(self, report: IntegrityReport) -> List[str]:
        """Generate recommended actions based on the report"""
        actions = []
        
        if not report.chain_valid:
            actions.extend([
                "CRITICAL: Backup database chain compromised",
                "Isolate backup server immediately",
                "Check for unauthorized access to backup system",
                "Preserve all logs for forensic analysis"
            ])
        
        if report.tampered_records > 0:
            actions.extend([
                "Records have been modified in the primary database",
                "Review recent access logs for suspicious activity",
                "Check for compromised credentials",
                "Consider restoring data from backup"
            ])
        
        if report.missing_records > 0:
            actions.extend([
                "Records have been deleted from primary database",
                "Attacker may be attempting to cover tracks",
                "Preserve backup database for evidence",
                "Initiate incident response procedure"
            ])
        
        actions.extend([
            "Review system access logs",
            "Check for unauthorized processes",
            "Consider isolating affected system",
            "Document all findings for forensics"
        ])
        
        return actions
    
    async def _send_alerts(self, alert: TamperingAlert):
        """Send alerts through configured channels"""
        for channel in self.alert_channels:
            try:
                if channel == 'log':
                    # Already logged above
                    pass
                elif channel == 'email':
                    await self._send_email_alert(alert)
                elif channel == 'slack':
                    await self._send_slack_alert(alert)
                elif channel == 'syslog':
                    await self._send_syslog_alert(alert)
                elif channel == 'webhook':
                    await self._send_webhook_alert(alert)
            except Exception as e:
                logger.error(f"Failed to send alert via {channel}: {e}")
    
    async def _send_email_alert(self, alert: TamperingAlert):
        """Send alert via email (implement with your email service)"""
        logger.info(f"Would send email alert: {alert.alert_id}")
        # TODO: Implement email sending
        # Example: await send_email(
        #     to=config.alert_email,
        #     subject=f"[{alert.severity}] Database Tampering Detected",
        #     body=alert.to_json()
        # )
    
    async def _send_slack_alert(self, alert: TamperingAlert):
        """Send alert to Slack (implement with Slack webhook)"""
        logger.info(f"Would send Slack alert: {alert.alert_id}")
        # TODO: Implement Slack webhook
        # Example: await post_to_slack(webhook_url, {
        #     "text": f"🚨 {alert.alert_type}",
        #     "blocks": [...]
        # })
    
    async def _send_syslog_alert(self, alert: TamperingAlert):
        """Send alert to syslog"""
        import syslog
        syslog.syslog(
            syslog.LOG_CRIT,
            f"ProjectLibra ALERT: {alert.alert_type} - {alert.tampered_count} tampered, "
            f"{alert.missing_count} deleted records"
        )
    
    async def _send_webhook_alert(self, alert: TamperingAlert):
        """Send alert via webhook"""
        logger.info(f"Would send webhook alert: {alert.alert_id}")
        # TODO: Implement generic webhook
    
    def stop(self):
        """Stop the monitoring service"""
        self._running = False
        logger.info("Integrity Monitor Service stopping...")
        logger.info(f"  Total checks performed: {self._check_count}")
        logger.info(f"  Total alerts raised: {self._alert_count}")
        if self._start_time:
            runtime = datetime.now() - self._start_time
            logger.info(f"  Total runtime: {runtime}")
    
    def get_last_report(self) -> Optional[IntegrityReport]:
        """Get the most recent integrity report"""
        return self._last_report
    
    def get_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        return {
            'running': self._running,
            'check_count': self._check_count,
            'alert_count': self._alert_count,
            'start_time': self._start_time.isoformat() if self._start_time else None,
            'last_check': self._last_report.check_timestamp.isoformat() if self._last_report else None,
            'last_status': self._last_report.overall_status if self._last_report else None
        }
    
    async def force_check(self) -> IntegrityReport:
        """Force an immediate integrity check"""
        logger.info("Forced integrity check requested")
        await self._perform_check()
        return self._last_report


class RealTimeIntegrityWatcher:
    """
    Real-time watcher that monitors for immediate tampering indicators.
    
    This complements the periodic IntegrityMonitorService by watching
    for suspicious patterns in real-time.
    """
    
    def __init__(self, dual_db_manager: DualDatabaseManager):
        self.db_manager = dual_db_manager
        self._watch_patterns = [
            'DELETE FROM',
            'DROP TABLE',
            'TRUNCATE',
            'UPDATE.*SET.*hash',
            'ALTER TABLE'
        ]
    
    async def watch_for_tampering(self, event_id: str) -> bool:
        """
        Watch a specific event for tampering.
        Returns True if tampering detected.
        """
        status = self.db_manager.check_single_record_integrity(event_id)
        
        if status != IntegrityStatus.VALID:
            logger.warning(f"Real-time tampering detected for event {event_id}: {status}")
            return True
        
        return False
    
    def check_write_consistency(self, event_id: str) -> bool:
        """
        Verify a recently written event exists in both databases.
        Call this immediately after writing to detect write failures.
        """
        primary_exists = self.db_manager.primary_db.get_event(event_id) is not None
        backup_exists = self.db_manager.backup_db.get_record(event_id) is not None
        
        if primary_exists != backup_exists:
            logger.error(f"Write consistency failure for {event_id}: "
                        f"primary={primary_exists}, backup={backup_exists}")
            return False
        
        return True


# Utility function to run the monitor
async def run_integrity_monitor(
    primary_db_path: str,
    backup_db_path: str,
    check_interval: int = 300,
    alert_callback: Optional[Callable] = None
):
    """
    Convenience function to run the integrity monitor.
    
    Example:
        asyncio.run(run_integrity_monitor(
            '/var/lib/projectlibra/primary.db',
            '/var/lib/projectlibra/backup/immutable.db',
            check_interval=60
        ))
    """
    db_manager = DualDatabaseManager(primary_db_path, backup_db_path)
    monitor = IntegrityMonitorService(
        db_manager,
        check_interval_seconds=check_interval,
        alert_callback=alert_callback
    )
    
    await monitor.start()
