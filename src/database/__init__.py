"""
ProjectLibra - Database Package
Dual database system with tamper-proof audit logging
"""

from .dual_db_manager import (
    DualDatabaseManager,
    PrimaryDB,
    ImmutableBackupDB,
    IntegrityStatus,
    IntegrityReport,
    AuditRecord,
    create_dual_db_system
)

__all__ = [
    'DualDatabaseManager',
    'PrimaryDB', 
    'ImmutableBackupDB',
    'IntegrityStatus',
    'IntegrityReport',
    'AuditRecord',
    'create_dual_db_system'
]
