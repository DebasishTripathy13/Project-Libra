"""
System Notification Service for ProjectLibra.

Provides desktop notifications with sound alerts for security events.
Works on Linux (notify-send), macOS (osascript), and Windows (plyer/win10toast).
"""

import os
import sys
import subprocess
import threading
from datetime import datetime
from typing import Optional, Callable, List, Dict, Any
from enum import Enum
from dataclasses import dataclass, field


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertType(Enum):
    """Types of security alerts."""
    TAMPERING_DETECTED = "tampering_detected"
    ANOMALY_DETECTED = "anomaly_detected"
    THREAT_DETECTED = "threat_detected"
    BRUTE_FORCE = "brute_force"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INTEGRITY_VIOLATION = "integrity_violation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SYSTEM_ALERT = "system_alert"


@dataclass
class SecurityAlert:
    """Security alert data structure."""
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = "ProjectLibra"
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'alert_type': self.alert_type.value,
            'severity': self.severity.value,
            'title': self.title,
            'message': self.message,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'details': self.details,
        }


class NotificationService:
    """
    Cross-platform notification service with sound alerts.
    
    Features:
    - Desktop notifications (Linux, macOS, Windows)
    - Sound alerts for critical events
    - Alert history tracking
    - Callback system for custom handlers
    """
    
    # Sound file paths (can be customized)
    SOUND_CRITICAL = "/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga"
    SOUND_HIGH = "/usr/share/sounds/freedesktop/stereo/bell.oga"
    SOUND_MEDIUM = "/usr/share/sounds/freedesktop/stereo/message.oga"
    SOUND_LOW = "/usr/share/sounds/freedesktop/stereo/complete.oga"
    
    # Fallback beep frequencies (Hz) for each severity
    BEEP_FREQUENCIES = {
        AlertSeverity.CRITICAL: [(1000, 200), (800, 200), (1000, 200)],  # Triple beep
        AlertSeverity.HIGH: [(800, 300), (800, 300)],  # Double beep
        AlertSeverity.MEDIUM: [(600, 200)],  # Single beep
        AlertSeverity.LOW: [(400, 100)],  # Soft beep
        AlertSeverity.INFO: [],  # No sound
    }
    
    def __init__(self, enable_sound: bool = True, enable_notifications: bool = True):
        self.enable_sound = enable_sound
        self.enable_notifications = enable_notifications
        self.alert_history: List[SecurityAlert] = []
        self.callbacks: List[Callable[[SecurityAlert], None]] = []
        self._platform = self._detect_platform()
        
    def _detect_platform(self) -> str:
        """Detect the current platform."""
        if sys.platform.startswith('linux'):
            return 'linux'
        elif sys.platform == 'darwin':
            return 'macos'
        elif sys.platform == 'win32':
            return 'windows'
        return 'unknown'
    
    def register_callback(self, callback: Callable[[SecurityAlert], None]):
        """Register a callback for alerts."""
        self.callbacks.append(callback)
    
    def alert(self, 
              alert_type: AlertType,
              severity: AlertSeverity,
              title: str,
              message: str,
              details: Optional[Dict[str, Any]] = None) -> SecurityAlert:
        """
        Send a security alert with notification and sound.
        
        Args:
            alert_type: Type of security alert
            severity: Severity level
            title: Alert title
            message: Alert message
            details: Additional details
            
        Returns:
            The created SecurityAlert object
        """
        alert = SecurityAlert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            details=details or {},
        )
        
        # Store in history
        self.alert_history.append(alert)
        
        # Send notification
        if self.enable_notifications:
            self._send_notification(alert)
        
        # Play sound
        if self.enable_sound and severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM]:
            self._play_alert_sound(severity)
        
        # Call registered callbacks
        for callback in self.callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"Callback error: {e}")
        
        return alert
    
    def _send_notification(self, alert: SecurityAlert):
        """Send desktop notification based on platform."""
        severity_icons = {
            AlertSeverity.CRITICAL: "🚨",
            AlertSeverity.HIGH: "⚠️",
            AlertSeverity.MEDIUM: "⚡",
            AlertSeverity.LOW: "ℹ️",
            AlertSeverity.INFO: "📝",
        }
        
        icon = severity_icons.get(alert.severity, "🔔")
        full_title = f"{icon} {alert.title}"
        
        # Calculate urgency for Linux
        urgency_map = {
            AlertSeverity.CRITICAL: "critical",
            AlertSeverity.HIGH: "critical",
            AlertSeverity.MEDIUM: "normal",
            AlertSeverity.LOW: "low",
            AlertSeverity.INFO: "low",
        }
        
        try:
            if self._platform == 'linux':
                self._notify_linux(full_title, alert.message, urgency_map[alert.severity])
            elif self._platform == 'macos':
                self._notify_macos(full_title, alert.message)
            elif self._platform == 'windows':
                self._notify_windows(full_title, alert.message)
            else:
                # Fallback: print to console
                self._notify_console(alert)
        except Exception as e:
            # Fallback to console
            self._notify_console(alert)
    
    def _notify_linux(self, title: str, message: str, urgency: str = "normal"):
        """Send notification on Linux using notify-send."""
        try:
            # Try notify-send first
            subprocess.run([
                'notify-send',
                '--urgency', urgency,
                '--app-name', 'ProjectLibra',
                '--icon', 'security-high',
                title,
                message
            ], check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Try zenity as fallback
            try:
                subprocess.Popen([
                    'zenity', '--notification',
                    '--text', f"{title}\n{message}"
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except FileNotFoundError:
                self._notify_console_simple(title, message)
    
    def _notify_macos(self, title: str, message: str):
        """Send notification on macOS using osascript."""
        try:
            script = f'display notification "{message}" with title "{title}" sound name "Basso"'
            subprocess.run(['osascript', '-e', script], check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            self._notify_console_simple(title, message)
    
    def _notify_windows(self, title: str, message: str):
        """Send notification on Windows."""
        try:
            # Try using PowerShell toast notification
            ps_script = f'''
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
            $textNodes = $template.GetElementsByTagName("text")
            $textNodes[0].AppendChild($template.CreateTextNode("{title}")) | Out-Null
            $textNodes[1].AppendChild($template.CreateTextNode("{message}")) | Out-Null
            $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("ProjectLibra").Show($toast)
            '''
            subprocess.run(['powershell', '-Command', ps_script], 
                         capture_output=True, check=True)
        except Exception:
            # Fallback: try plyer if available
            try:
                from plyer import notification
                notification.notify(
                    title=title,
                    message=message,
                    app_name='ProjectLibra',
                    timeout=10
                )
            except ImportError:
                self._notify_console_simple(title, message)
    
    def _notify_console(self, alert: SecurityAlert):
        """Fallback notification to console with colors."""
        colors = {
            AlertSeverity.CRITICAL: '\033[91m',  # Red
            AlertSeverity.HIGH: '\033[93m',      # Yellow
            AlertSeverity.MEDIUM: '\033[94m',    # Blue
            AlertSeverity.LOW: '\033[92m',       # Green
            AlertSeverity.INFO: '\033[97m',      # White
        }
        reset = '\033[0m'
        color = colors.get(alert.severity, reset)
        
        print(f"\n{color}{'═' * 60}")
        print(f"🔔 ALERT: {alert.title}")
        print(f"{'─' * 60}")
        print(f"Severity: {alert.severity.value.upper()}")
        print(f"Type: {alert.alert_type.value}")
        print(f"Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Message: {alert.message}")
        print(f"{'═' * 60}{reset}\n")
    
    def _notify_console_simple(self, title: str, message: str):
        """Simple console notification."""
        print(f"\n🔔 {title}: {message}\n")
    
    def _play_alert_sound(self, severity: AlertSeverity):
        """Play alert sound based on severity."""
        # Run sound in background thread to not block
        thread = threading.Thread(target=self._play_sound_thread, args=(severity,))
        thread.daemon = True
        thread.start()
    
    def _play_sound_thread(self, severity: AlertSeverity):
        """Thread function to play sound."""
        try:
            if self._platform == 'linux':
                self._play_sound_linux(severity)
            elif self._platform == 'macos':
                self._play_sound_macos(severity)
            elif self._platform == 'windows':
                self._play_sound_windows(severity)
        except Exception:
            # Fallback to terminal bell
            self._play_terminal_bell(severity)
    
    def _play_sound_linux(self, severity: AlertSeverity):
        """Play sound on Linux."""
        sound_files = {
            AlertSeverity.CRITICAL: self.SOUND_CRITICAL,
            AlertSeverity.HIGH: self.SOUND_HIGH,
            AlertSeverity.MEDIUM: self.SOUND_MEDIUM,
            AlertSeverity.LOW: self.SOUND_LOW,
        }
        
        sound_file = sound_files.get(severity)
        
        # Try paplay (PulseAudio)
        if sound_file and os.path.exists(sound_file):
            try:
                subprocess.run(['paplay', sound_file], 
                             capture_output=True, check=True, timeout=5)
                return
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        
        # Try aplay
        try:
            subprocess.run(['aplay', '-q', '/usr/share/sounds/alsa/Front_Center.wav'],
                         capture_output=True, timeout=5)
            return
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Try spd-say for voice alert on critical
        if severity == AlertSeverity.CRITICAL:
            try:
                subprocess.run(['spd-say', '-w', 'Security Alert! Tampering detected!'],
                             capture_output=True, timeout=10)
                return
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        
        # Fallback to beep
        self._play_terminal_bell(severity)
    
    def _play_sound_macos(self, severity: AlertSeverity):
        """Play sound on macOS."""
        sounds = {
            AlertSeverity.CRITICAL: 'Basso',
            AlertSeverity.HIGH: 'Sosumi',
            AlertSeverity.MEDIUM: 'Ping',
            AlertSeverity.LOW: 'Pop',
        }
        sound = sounds.get(severity, 'Ping')
        
        try:
            # Repeat for critical
            count = 3 if severity == AlertSeverity.CRITICAL else 1
            for _ in range(count):
                subprocess.run(['afplay', f'/System/Library/Sounds/{sound}.aiff'],
                             capture_output=True, timeout=5)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            self._play_terminal_bell(severity)
    
    def _play_sound_windows(self, severity: AlertSeverity):
        """Play sound on Windows."""
        try:
            import winsound
            
            if severity == AlertSeverity.CRITICAL:
                # Play multiple beeps for critical
                for _ in range(3):
                    winsound.Beep(1000, 200)
                    winsound.Beep(800, 200)
            elif severity == AlertSeverity.HIGH:
                winsound.Beep(800, 300)
                winsound.Beep(800, 300)
            elif severity == AlertSeverity.MEDIUM:
                winsound.Beep(600, 200)
            else:
                winsound.MessageBeep()
        except ImportError:
            self._play_terminal_bell(severity)
    
    def _play_terminal_bell(self, severity: AlertSeverity):
        """Play terminal bell as fallback."""
        beep_count = {
            AlertSeverity.CRITICAL: 3,
            AlertSeverity.HIGH: 2,
            AlertSeverity.MEDIUM: 1,
            AlertSeverity.LOW: 1,
            AlertSeverity.INFO: 0,
        }
        
        count = beep_count.get(severity, 1)
        for _ in range(count):
            print('\a', end='', flush=True)
            if count > 1:
                import time
                time.sleep(0.3)
    
    # Convenience methods for common alerts
    
    def alert_tampering(self, message: str, details: Optional[Dict] = None):
        """Send tampering detection alert."""
        return self.alert(
            AlertType.TAMPERING_DETECTED,
            AlertSeverity.CRITICAL,
            "🚨 DATABASE TAMPERING DETECTED",
            message,
            details
        )
    
    def alert_anomaly(self, message: str, score: float, details: Optional[Dict] = None):
        """Send anomaly detection alert."""
        severity = AlertSeverity.HIGH if score > 0.8 else AlertSeverity.MEDIUM
        return self.alert(
            AlertType.ANOMALY_DETECTED,
            severity,
            "⚠️ ANOMALY DETECTED",
            f"{message} (score: {score:.2f})",
            details
        )
    
    def alert_threat(self, threat_type: str, message: str, 
                     severity: AlertSeverity = AlertSeverity.HIGH,
                     details: Optional[Dict] = None):
        """Send threat detection alert."""
        return self.alert(
            AlertType.THREAT_DETECTED,
            severity,
            f"🎯 THREAT: {threat_type}",
            message,
            details
        )
    
    def alert_brute_force(self, source_ip: str, attempts: int, 
                          details: Optional[Dict] = None):
        """Send brute force attack alert."""
        return self.alert(
            AlertType.BRUTE_FORCE,
            AlertSeverity.HIGH,
            "🔓 BRUTE FORCE ATTACK",
            f"Multiple failed attempts from {source_ip} ({attempts} attempts)",
            details
        )
    
    def alert_privilege_escalation(self, user: str, action: str,
                                   details: Optional[Dict] = None):
        """Send privilege escalation alert."""
        return self.alert(
            AlertType.PRIVILEGE_ESCALATION,
            AlertSeverity.CRITICAL,
            "👑 PRIVILEGE ESCALATION",
            f"User '{user}' attempted: {action}",
            details
        )
    
    def alert_integrity_violation(self, component: str, message: str,
                                  details: Optional[Dict] = None):
        """Send integrity violation alert."""
        return self.alert(
            AlertType.INTEGRITY_VIOLATION,
            AlertSeverity.CRITICAL,
            "🔐 INTEGRITY VIOLATION",
            f"{component}: {message}",
            details
        )
    
    def get_recent_alerts(self, count: int = 10, 
                          severity: Optional[AlertSeverity] = None) -> List[SecurityAlert]:
        """Get recent alerts from history."""
        alerts = self.alert_history
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return alerts[-count:]
    
    def clear_history(self):
        """Clear alert history."""
        self.alert_history.clear()


# Global notification service instance
_notification_service: Optional[NotificationService] = None


def get_notification_service() -> NotificationService:
    """Get the global notification service instance."""
    global _notification_service
    if _notification_service is None:
        _notification_service = NotificationService()
    return _notification_service


def send_alert(alert_type: AlertType, severity: AlertSeverity, 
               title: str, message: str, details: Optional[Dict] = None) -> SecurityAlert:
    """Convenience function to send an alert."""
    return get_notification_service().alert(alert_type, severity, title, message, details)


# Quick alert functions
def alert_critical(title: str, message: str):
    """Send a critical alert."""
    return send_alert(AlertType.SYSTEM_ALERT, AlertSeverity.CRITICAL, title, message)


def alert_high(title: str, message: str):
    """Send a high severity alert."""
    return send_alert(AlertType.SYSTEM_ALERT, AlertSeverity.HIGH, title, message)


def alert_medium(title: str, message: str):
    """Send a medium severity alert."""
    return send_alert(AlertType.SYSTEM_ALERT, AlertSeverity.MEDIUM, title, message)


def alert_low(title: str, message: str):
    """Send a low severity alert."""
    return send_alert(AlertType.SYSTEM_ALERT, AlertSeverity.LOW, title, message)


if __name__ == '__main__':
    # Test notifications
    print("Testing ProjectLibra Notification Service...")
    
    service = NotificationService()
    
    print("\n1. Testing INFO alert...")
    service.alert(AlertType.SYSTEM_ALERT, AlertSeverity.INFO, 
                  "Info Alert", "This is an informational message")
    
    print("\n2. Testing MEDIUM alert...")
    service.alert(AlertType.ANOMALY_DETECTED, AlertSeverity.MEDIUM,
                  "Anomaly Detected", "Unusual login pattern detected")
    
    print("\n3. Testing HIGH alert...")
    service.alert_threat("Brute Force", "Multiple failed SSH attempts detected")
    
    print("\n4. Testing CRITICAL alert...")
    service.alert_tampering("Database record modified outside of application!")
    
    print("\nAll tests complete!")
