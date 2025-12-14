#!/usr/bin/env python3
"""
ProjectLibra - System Updates Demo
Demonstrates the system update and patch management capabilities
"""

import asyncio
from datetime import datetime

print('=' * 60)
print('  ProjectLibra System Updates Demo')
print('=' * 60)

from src.agents.maintenance_agent import (
    MaintenanceAgent, 
    ActionType, 
    MaintenanceAction, 
    ActionStatus
)

async def main():
    # Create agent in dry-run mode (safe for demo)
    agent = MaintenanceAgent(
        auto_remediate=False,
        dry_run=False,  # Actually check for updates (read-only operation)
        allowed_actions={
            ActionType.CHECK_UPDATES,
            ActionType.PATCH_REPORT,
            ActionType.ALERT_ADMIN,
            ActionType.LOG_EVENT,
        }
    )
    
    # Detect package manager
    pkg_manager = agent._detect_package_manager()
    print(f"\n📦 Detected Package Manager: {pkg_manager}")
    print(f"🖥️  Platform: {agent._platform}")
    
    if pkg_manager in ['unsupported', 'unknown']:
        print("\n⚠️  System updates not available on this platform")
        print("   (Requires apt, dnf, yum, pacman, or zypper)")
        
        # Show what would happen on a Linux system
        print("\n📋 Available System Update Actions:")
        print("-" * 40)
        actions = {
            'CHECK_UPDATES': 'Refresh package cache and list available updates',
            'APPLY_UPDATES': 'Install all available updates (requires approval)',
            'SECURITY_PATCH': 'Install security-only patches',
            'PATCH_REPORT': 'Generate vulnerability/patch status report',
        }
        for name, desc in actions.items():
            print(f"  ✓ {name}: {desc}")
        return
    
    # Check for updates (read-only, safe operation)
    print("\n🔍 Checking for available updates...")
    print("-" * 40)
    
    check_action = MaintenanceAction(
        action_id='check-001',
        action_type=ActionType.CHECK_UPDATES,
        target='system',
        parameters={},
    )
    
    await agent._execute_check_updates(check_action)
    
    if check_action.status == ActionStatus.FAILED:
        print(f"❌ Error: {check_action.error}")
    else:
        result = check_action.result
        if isinstance(result, dict):
            print(f"📊 Package Manager: {result.get('package_manager')}")
            print(f"📦 Updates Available: {result.get('updates_available', 0)}")
            
            packages = result.get('packages', [])
            if packages:
                print(f"\n📋 Upgradable Packages (showing first 10):")
                for pkg in packages[:10]:
                    print(f"   • {pkg}")
                if len(packages) > 10:
                    print(f"   ... and {len(packages) - 10} more")
        else:
            print(result)
    
    # Generate patch report
    print("\n\n📊 Generating Patch Report...")
    print("-" * 40)
    
    report_action = MaintenanceAction(
        action_id='report-001',
        action_type=ActionType.PATCH_REPORT,
        target='system',
        parameters={},
    )
    
    await agent._execute_patch_report(report_action)
    
    if report_action.status == ActionStatus.FAILED:
        print(f"❌ Error: {report_action.error}")
    else:
        report = report_action.result
        if isinstance(report, dict):
            print(f"🖥️  Hostname: {report.get('hostname')}")
            print(f"🐧 Kernel: {report.get('kernel')}")
            
            summary = report.get('summary', {})
            print(f"\n📈 Summary:")
            print(f"   Total Updates: {summary.get('total_updates', 'N/A')}")
            print(f"   Security Updates: {summary.get('security_updates', 'N/A')}")
            
            security = report.get('security_updates', [])
            if security and security[0]:
                print(f"\n🔒 Security Updates (first 5):")
                for s in security[:5]:
                    if s.strip():
                        print(f"   • {s.strip()[:70]}")
    
    print("\n" + "=" * 60)
    print("  ⚠️  To apply updates, use with approval workflow:")
    print("     agent.auto_remediate = True")
    print("     agent.require_approval_threshold = 0.5")
    print("=" * 60)

if __name__ == '__main__':
    asyncio.run(main())
