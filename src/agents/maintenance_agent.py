"""
Maintenance Agent for Self-Healing and Remediation.

Handles automated responses to security threats,
system maintenance, and self-healing capabilities.
"""

import asyncio
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
import platform
import logging

from .base_agent import BaseAgent, AgentMessage, AgentState, MessagePriority


class ActionType(Enum):
    """Types of maintenance actions."""
    BLOCK_IP = 'block_ip'
    KILL_PROCESS = 'kill_process'
    DISABLE_USER = 'disable_user'
    QUARANTINE_FILE = 'quarantine_file'
    RESTART_SERVICE = 'restart_service'
    UPDATE_FIREWALL = 'update_firewall'
    ALERT_ADMIN = 'alert_admin'
    LOG_EVENT = 'log_event'
    CUSTOM = 'custom'
    # System update actions
    CHECK_UPDATES = 'check_updates'
    APPLY_UPDATES = 'apply_updates'
    SECURITY_PATCH = 'security_patch'
    PATCH_REPORT = 'patch_report'


class ActionStatus(Enum):
    """Status of maintenance action."""
    PENDING = 'pending'
    IN_PROGRESS = 'in_progress'
    COMPLETED = 'completed'
    FAILED = 'failed'
    REQUIRES_APPROVAL = 'requires_approval'
    ROLLED_BACK = 'rolled_back'


@dataclass
class MaintenanceAction:
    """A maintenance or remediation action."""
    
    action_id: str
    action_type: ActionType
    target: str
    parameters: Dict[str, Any]
    status: ActionStatus = ActionStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[str] = None
    error: Optional[str] = None
    requires_approval: bool = False
    approved_by: Optional[str] = None
    rollback_action: Optional['MaintenanceAction'] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'action_id': self.action_id,
            'action_type': self.action_type.value,
            'target': self.target,
            'parameters': self.parameters,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'executed_at': self.executed_at.isoformat() if self.executed_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'result': self.result,
            'error': self.error,
            'requires_approval': self.requires_approval,
        }


class MaintenanceAgent(BaseAgent):
    """
    Agent for automated maintenance and remediation.
    
    Capabilities:
    - Automated threat response (with safety controls)
    - Process termination
    - IP blocking
    - User disabling
    - Service management
    - Firewall updates
    - Self-healing actions
    """
    
    # Message types
    MSG_ACTION_REQUESTED = 'maintenance.action_requested'
    MSG_ACTION_EXECUTED = 'maintenance.action_executed'
    MSG_ACTION_FAILED = 'maintenance.action_failed'
    MSG_APPROVAL_REQUIRED = 'maintenance.approval_required'
    
    def __init__(
        self,
        auto_remediate: bool = False,
        require_approval_threshold: float = 0.8,
        dry_run: bool = True,
        allowed_actions: Optional[Set[ActionType]] = None,
        blocked_targets: Optional[Set[str]] = None,
        message_handler: Optional[Callable[[AgentMessage], None]] = None,
    ):
        """
        Initialize maintenance agent.
        
        Args:
            auto_remediate: Enable automatic remediation (dangerous!)
            require_approval_threshold: Threat level requiring approval
            dry_run: Only simulate actions, don't execute
            allowed_actions: Set of allowed action types
            blocked_targets: Targets that cannot be acted upon
            message_handler: Callback for outbound messages
        """
        super().__init__(
            name='MaintenanceAgent',
            description='Automated maintenance and remediation',
            message_handler=message_handler,
        )
        
        self.auto_remediate = auto_remediate
        self.require_approval_threshold = require_approval_threshold
        self.dry_run = dry_run
        
        # Safety controls
        self.allowed_actions = allowed_actions or {
            ActionType.LOG_EVENT,
            ActionType.ALERT_ADMIN,
        }
        self.blocked_targets = blocked_targets or {
            'root', 'SYSTEM', 'Administrator',
            '127.0.0.1', 'localhost',
            'systemd', 'init', 'kernel',
        }
        
        # Action tracking
        self._action_counter = 0
        self._pending_actions: Dict[str, MaintenanceAction] = {}
        self._completed_actions: List[MaintenanceAction] = []
        self._max_completed = 1000
        
        # Platform
        self._platform = platform.system().lower()
    
    async def _initialize(self) -> None:
        """Initialize agent."""
        self.logger.info("Initializing maintenance agent...")
        self.logger.info(f"Platform: {self._platform}")
        self.logger.info(f"Auto-remediate: {self.auto_remediate}")
        self.logger.info(f"Dry run: {self.dry_run}")
        self.logger.info(f"Allowed actions: {[a.value for a in self.allowed_actions]}")
        
        # Subscribe to relevant messages
        self.subscribe('threat.assessment')
        self.subscribe('maintenance.request')
        self.subscribe('maintenance.approve')
        self.subscribe('maintenance.rollback')
    
    async def _cleanup(self) -> None:
        """Clean up resources."""
        self.logger.info("Cleaning up maintenance agent...")
    
    async def _handle_message(self, message: AgentMessage) -> None:
        """Handle incoming messages."""
        if message.message_type == 'threat.assessment':
            await self._handle_threat_assessment(message.payload)
        
        elif message.message_type == 'maintenance.request':
            await self._handle_action_request(message.payload)
        
        elif message.message_type == 'maintenance.approve':
            await self._handle_approval(message.payload)
        
        elif message.message_type == 'maintenance.rollback':
            await self._handle_rollback(message.payload)
    
    async def _handle_threat_assessment(self, assessment: Dict[str, Any]) -> None:
        """Handle threat assessment and determine response."""
        threat_level = assessment.get('threat_level', 'none')
        confidence = assessment.get('confidence', 0)
        
        if not self.auto_remediate:
            # Just log the assessment
            self.logger.info(f"Threat assessment received: {threat_level} (confidence: {confidence:.2f})")
            return
        
        # Determine appropriate response
        actions = self._determine_response(assessment)
        
        for action in actions:
            if confidence >= self.require_approval_threshold:
                action.requires_approval = True
                action.status = ActionStatus.REQUIRES_APPROVAL
                self._pending_actions[action.action_id] = action
                
                self.broadcast(
                    self.MSG_APPROVAL_REQUIRED,
                    action.to_dict(),
                    priority=MessagePriority.HIGH,
                )
            else:
                await self._execute_action(action)
    
    async def _handle_action_request(self, request: Dict[str, Any]) -> None:
        """Handle explicit action request."""
        action = self._create_action(
            action_type=ActionType(request.get('action_type', 'log_event')),
            target=request.get('target', ''),
            parameters=request.get('parameters', {}),
            requires_approval=request.get('requires_approval', True),
        )
        
        if action.requires_approval:
            action.status = ActionStatus.REQUIRES_APPROVAL
            self._pending_actions[action.action_id] = action
            
            self.broadcast(
                self.MSG_APPROVAL_REQUIRED,
                action.to_dict(),
                priority=MessagePriority.HIGH,
            )
        else:
            await self._execute_action(action)
    
    async def _handle_approval(self, approval: Dict[str, Any]) -> None:
        """Handle action approval."""
        action_id = approval.get('action_id')
        approved_by = approval.get('approved_by', 'system')
        
        if action_id not in self._pending_actions:
            self.logger.warning(f"Action {action_id} not found for approval")
            return
        
        action = self._pending_actions.pop(action_id)
        action.approved_by = approved_by
        action.status = ActionStatus.PENDING
        
        await self._execute_action(action)
    
    async def _handle_rollback(self, rollback: Dict[str, Any]) -> None:
        """Handle rollback request."""
        action_id = rollback.get('action_id')
        
        # Find the action to rollback
        action = next(
            (a for a in self._completed_actions if a.action_id == action_id),
            None
        )
        
        if not action or not action.rollback_action:
            self.logger.warning(f"Cannot rollback action {action_id}")
            return
        
        await self._execute_action(action.rollback_action)
        action.status = ActionStatus.ROLLED_BACK
    
    def _determine_response(self, assessment: Dict[str, Any]) -> List[MaintenanceAction]:
        """Determine appropriate response actions."""
        actions = []
        threat_level = assessment.get('threat_level', 'none')
        
        # Always log
        actions.append(self._create_action(
            ActionType.LOG_EVENT,
            'security_log',
            {'assessment': assessment},
        ))
        
        if threat_level in ('high', 'critical'):
            actions.append(self._create_action(
                ActionType.ALERT_ADMIN,
                'admin_team',
                {'message': assessment.get('summary', 'Threat detected')},
            ))
        
        # Check for specific indicators that warrant action
        indicators = assessment.get('indicators', [])
        
        for indicator in indicators:
            indicator_lower = indicator.lower()
            
            # IP-based threats
            if 'ip' in indicator_lower and ActionType.BLOCK_IP in self.allowed_actions:
                import re
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', indicator)
                for ip in ips:
                    if ip not in self.blocked_targets:
                        actions.append(self._create_action(
                            ActionType.BLOCK_IP,
                            ip,
                            {'duration': 3600, 'reason': indicator},
                        ))
            
            # Process-based threats
            if 'process' in indicator_lower and ActionType.KILL_PROCESS in self.allowed_actions:
                # Would need to extract PID from indicator
                pass
        
        return actions
    
    def _create_action(
        self,
        action_type: ActionType,
        target: str,
        parameters: Dict[str, Any],
        requires_approval: bool = False,
    ) -> MaintenanceAction:
        """Create a maintenance action."""
        self._action_counter += 1
        
        # Check if action type is allowed
        if action_type not in self.allowed_actions:
            self.logger.warning(f"Action type {action_type.value} not allowed")
            action_type = ActionType.LOG_EVENT
        
        # Check if target is blocked
        if target in self.blocked_targets:
            self.logger.warning(f"Target {target} is blocked")
            target = f"BLOCKED:{target}"
            action_type = ActionType.LOG_EVENT
        
        action = MaintenanceAction(
            action_id=f"ACT-{self._action_counter:06d}",
            action_type=action_type,
            target=target,
            parameters=parameters,
            requires_approval=requires_approval,
        )
        
        # Create rollback action if applicable
        action.rollback_action = self._create_rollback(action)
        
        return action
    
    def _create_rollback(self, action: MaintenanceAction) -> Optional[MaintenanceAction]:
        """Create rollback action for an action."""
        if action.action_type == ActionType.BLOCK_IP:
            return MaintenanceAction(
                action_id=f"{action.action_id}-ROLLBACK",
                action_type=ActionType.BLOCK_IP,
                target=action.target,
                parameters={'unblock': True},
            )
        elif action.action_type == ActionType.DISABLE_USER:
            return MaintenanceAction(
                action_id=f"{action.action_id}-ROLLBACK",
                action_type=ActionType.DISABLE_USER,
                target=action.target,
                parameters={'enable': True},
            )
        return None
    
    async def _execute_action(self, action: MaintenanceAction) -> None:
        """Execute a maintenance action."""
        action.status = ActionStatus.IN_PROGRESS
        action.executed_at = datetime.now()
        
        self.logger.info(f"Executing action: {action.action_type.value} on {action.target}")
        
        if self.dry_run:
            self.logger.info(f"DRY RUN: Would execute {action.action_type.value} on {action.target}")
            action.status = ActionStatus.COMPLETED
            action.completed_at = datetime.now()
            action.result = "Dry run - no action taken"
            self._record_completed(action)
            return
        
        try:
            if action.action_type == ActionType.BLOCK_IP:
                await self._execute_block_ip(action)
            elif action.action_type == ActionType.KILL_PROCESS:
                await self._execute_kill_process(action)
            elif action.action_type == ActionType.DISABLE_USER:
                await self._execute_disable_user(action)
            elif action.action_type == ActionType.RESTART_SERVICE:
                await self._execute_restart_service(action)
            elif action.action_type == ActionType.ALERT_ADMIN:
                await self._execute_alert_admin(action)
            elif action.action_type == ActionType.LOG_EVENT:
                await self._execute_log_event(action)
            elif action.action_type == ActionType.CHECK_UPDATES:
                await self._execute_check_updates(action)
            elif action.action_type == ActionType.APPLY_UPDATES:
                await self._execute_apply_updates(action)
            elif action.action_type == ActionType.SECURITY_PATCH:
                await self._execute_security_patch(action)
            elif action.action_type == ActionType.PATCH_REPORT:
                await self._execute_patch_report(action)
            else:
                action.status = ActionStatus.FAILED
                action.error = f"Unsupported action type: {action.action_type.value}"
            
            if action.status != ActionStatus.FAILED:
                action.status = ActionStatus.COMPLETED
                action.completed_at = datetime.now()
            
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error = str(e)
            self.logger.error(f"Action failed: {e}")
        
        self._record_completed(action)
        
        # Broadcast result
        if action.status == ActionStatus.COMPLETED:
            self.broadcast(
                self.MSG_ACTION_EXECUTED,
                action.to_dict(),
                priority=MessagePriority.NORMAL,
            )
        else:
            self.broadcast(
                self.MSG_ACTION_FAILED,
                action.to_dict(),
                priority=MessagePriority.HIGH,
            )
    
    async def _execute_block_ip(self, action: MaintenanceAction) -> None:
        """Block an IP address."""
        ip = action.target
        unblock = action.parameters.get('unblock', False)
        
        if self._platform == 'linux':
            if unblock:
                cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
            else:
                cmd = ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
            
            result = await asyncio.to_thread(
                subprocess.run, cmd, capture_output=True, text=True
            )
            
            if result.returncode != 0:
                raise Exception(f"iptables failed: {result.stderr}")
            
            action.result = f"IP {ip} {'unblocked' if unblock else 'blocked'}"
        else:
            action.result = f"IP blocking not implemented for {self._platform}"
    
    async def _execute_kill_process(self, action: MaintenanceAction) -> None:
        """Kill a process."""
        pid = action.parameters.get('pid')
        
        if not pid:
            raise Exception("PID not specified")
        
        import signal
        import os
        
        try:
            os.kill(int(pid), signal.SIGTERM)
            action.result = f"Process {pid} terminated"
        except ProcessLookupError:
            action.result = f"Process {pid} not found"
        except PermissionError:
            raise Exception(f"Permission denied to kill process {pid}")
    
    async def _execute_disable_user(self, action: MaintenanceAction) -> None:
        """Disable a user account."""
        username = action.target
        enable = action.parameters.get('enable', False)
        
        if self._platform == 'linux':
            if enable:
                cmd = ['usermod', '-U', username]
            else:
                cmd = ['usermod', '-L', username]
            
            result = await asyncio.to_thread(
                subprocess.run, cmd, capture_output=True, text=True
            )
            
            if result.returncode != 0:
                raise Exception(f"usermod failed: {result.stderr}")
            
            action.result = f"User {username} {'enabled' if enable else 'disabled'}"
        else:
            action.result = f"User management not implemented for {self._platform}"
    
    async def _execute_restart_service(self, action: MaintenanceAction) -> None:
        """Restart a system service."""
        service = action.target
        
        if self._platform == 'linux':
            cmd = ['systemctl', 'restart', service]
            
            result = await asyncio.to_thread(
                subprocess.run, cmd, capture_output=True, text=True
            )
            
            if result.returncode != 0:
                raise Exception(f"systemctl failed: {result.stderr}")
            
            action.result = f"Service {service} restarted"
        else:
            action.result = f"Service management not implemented for {self._platform}"
    
    async def _execute_alert_admin(self, action: MaintenanceAction) -> None:
        """Send alert to administrators."""
        message = action.parameters.get('message', 'Security alert')
        
        # In production, this would integrate with alerting systems
        self.logger.warning(f"ADMIN ALERT: {message}")
        action.result = f"Alert sent: {message}"
    
    async def _execute_log_event(self, action: MaintenanceAction) -> None:
        """Log a security event."""
        self.logger.info(f"Security event logged: {action.target}")
        action.result = "Event logged"
    
    def _record_completed(self, action: MaintenanceAction) -> None:
        """Record completed action."""
        self._completed_actions.append(action)
        if len(self._completed_actions) > self._max_completed:
            self._completed_actions.pop(0)
    
    def get_pending_actions(self) -> List[Dict[str, Any]]:
        """Get pending actions requiring approval."""
        return [a.to_dict() for a in self._pending_actions.values()]
    
    def get_recent_actions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent completed actions."""
        return [a.to_dict() for a in self._completed_actions[-limit:]]

    # ==================== System Update Methods ====================
    
    def _detect_package_manager(self) -> str:
        """Detect the system's package manager."""
        import shutil
        
        if self._platform != 'linux':
            return 'unsupported'
        
        # Check for package managers in order of preference
        if shutil.which('apt-get'):
            return 'apt'
        elif shutil.which('dnf'):
            return 'dnf'
        elif shutil.which('yum'):
            return 'yum'
        elif shutil.which('pacman'):
            return 'pacman'
        elif shutil.which('zypper'):
            return 'zypper'
        else:
            return 'unknown'
    
    async def _execute_check_updates(self, action: MaintenanceAction) -> None:
        """Check for available system updates."""
        pkg_manager = self._detect_package_manager()
        
        if pkg_manager == 'unsupported':
            action.result = f"System updates not supported on {self._platform}"
            return
        
        if pkg_manager == 'unknown':
            action.status = ActionStatus.FAILED
            action.error = "Could not detect package manager"
            return
        
        # Commands to check for updates
        check_commands = {
            'apt': ['apt-get', 'update', '-qq'],
            'dnf': ['dnf', 'check-update', '-q'],
            'yum': ['yum', 'check-update', '-q'],
            'pacman': ['pacman', '-Sy'],
            'zypper': ['zypper', 'refresh'],
        }
        
        list_commands = {
            'apt': ['apt', 'list', '--upgradable'],
            'dnf': ['dnf', 'list', 'updates', '-q'],
            'yum': ['yum', 'list', 'updates', '-q'],
            'pacman': ['pacman', '-Qu'],
            'zypper': ['zypper', 'list-updates'],
        }
        
        try:
            # Refresh package cache
            refresh_cmd = check_commands.get(pkg_manager)
            if refresh_cmd:
                await asyncio.to_thread(
                    subprocess.run, refresh_cmd, capture_output=True, text=True
                )
            
            # List available updates
            list_cmd = list_commands.get(pkg_manager)
            result = await asyncio.to_thread(
                subprocess.run, list_cmd, capture_output=True, text=True
            )
            
            updates = result.stdout.strip().split('\n') if result.stdout.strip() else []
            updates = [u for u in updates if u and not u.startswith('Listing')]
            
            action.result = {
                'package_manager': pkg_manager,
                'updates_available': len(updates),
                'packages': updates[:20],  # Limit to first 20
                'message': f"Found {len(updates)} available updates"
            }
            
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error = f"Failed to check updates: {str(e)}"
    
    async def _execute_apply_updates(self, action: MaintenanceAction) -> None:
        """Apply system updates (requires approval)."""
        pkg_manager = self._detect_package_manager()
        packages = action.parameters.get('packages', [])  # Specific packages or empty for all
        security_only = action.parameters.get('security_only', False)
        
        if pkg_manager == 'unsupported':
            action.result = f"System updates not supported on {self._platform}"
            return
        
        if pkg_manager == 'unknown':
            action.status = ActionStatus.FAILED
            action.error = "Could not detect package manager"
            return
        
        # Build update command
        if pkg_manager == 'apt':
            if packages:
                cmd = ['apt-get', 'install', '-y'] + packages
            elif security_only:
                cmd = ['apt-get', 'upgrade', '-y', '-o', 'Dpkg::Options::=--force-confold']
            else:
                cmd = ['apt-get', 'upgrade', '-y', '-o', 'Dpkg::Options::=--force-confold']
        
        elif pkg_manager == 'dnf':
            if packages:
                cmd = ['dnf', 'update', '-y'] + packages
            elif security_only:
                cmd = ['dnf', 'update', '-y', '--security']
            else:
                cmd = ['dnf', 'update', '-y']
        
        elif pkg_manager == 'yum':
            if packages:
                cmd = ['yum', 'update', '-y'] + packages
            elif security_only:
                cmd = ['yum', 'update', '-y', '--security']
            else:
                cmd = ['yum', 'update', '-y']
        
        elif pkg_manager == 'pacman':
            cmd = ['pacman', '-Syu', '--noconfirm']
        
        elif pkg_manager == 'zypper':
            if security_only:
                cmd = ['zypper', '-n', 'patch', '--category', 'security']
            else:
                cmd = ['zypper', '-n', 'update']
        
        else:
            action.status = ActionStatus.FAILED
            action.error = f"Update not implemented for {pkg_manager}"
            return
        
        try:
            self.logger.info(f"Applying updates: {' '.join(cmd)}")
            result = await asyncio.to_thread(
                subprocess.run, cmd, capture_output=True, text=True, timeout=3600
            )
            
            if result.returncode == 0:
                action.result = {
                    'package_manager': pkg_manager,
                    'command': ' '.join(cmd),
                    'status': 'success',
                    'output': result.stdout[-2000:] if result.stdout else 'No output',
                    'message': 'Updates applied successfully'
                }
            else:
                action.status = ActionStatus.FAILED
                action.error = f"Update failed: {result.stderr[-500:]}"
                
        except subprocess.TimeoutExpired:
            action.status = ActionStatus.FAILED
            action.error = "Update timed out after 1 hour"
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error = f"Update failed: {str(e)}"
    
    async def _execute_security_patch(self, action: MaintenanceAction) -> None:
        """Apply security-only patches."""
        action.parameters['security_only'] = True
        await self._execute_apply_updates(action)
    
    async def _execute_patch_report(self, action: MaintenanceAction) -> None:
        """Generate a patch/vulnerability report."""
        pkg_manager = self._detect_package_manager()
        
        if pkg_manager == 'unsupported':
            action.result = f"Patch report not supported on {self._platform}"
            return
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'platform': self._platform,
            'package_manager': pkg_manager,
            'hostname': platform.node(),
            'kernel': platform.release(),
            'updates': {},
            'security_updates': [],
        }
        
        try:
            # Get list of available updates
            if pkg_manager == 'apt':
                # Get all upgradable
                result = await asyncio.to_thread(
                    subprocess.run, 
                    ['apt', 'list', '--upgradable'],
                    capture_output=True, text=True
                )
                updates = [l for l in result.stdout.split('\n') if '/' in l]
                report['updates']['all'] = updates[:50]
                
                # Check for security updates
                result = await asyncio.to_thread(
                    subprocess.run,
                    ['apt-get', '-s', 'upgrade'],
                    capture_output=True, text=True
                )
                security_lines = [l for l in result.stdout.split('\n') 
                                 if 'security' in l.lower()]
                report['security_updates'] = security_lines[:20]
                
            elif pkg_manager in ['dnf', 'yum']:
                # Security updates
                cmd = [pkg_manager, 'updateinfo', 'list', 'security']
                result = await asyncio.to_thread(
                    subprocess.run, cmd, capture_output=True, text=True
                )
                report['security_updates'] = result.stdout.strip().split('\n')[:30]
                
                # All updates
                cmd = [pkg_manager, 'list', 'updates', '-q']
                result = await asyncio.to_thread(
                    subprocess.run, cmd, capture_output=True, text=True
                )
                report['updates']['all'] = result.stdout.strip().split('\n')[:50]
            
            report['summary'] = {
                'total_updates': len(report['updates'].get('all', [])),
                'security_updates': len(report['security_updates']),
            }
            
            action.result = report
            
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error = f"Failed to generate report: {str(e)}"

