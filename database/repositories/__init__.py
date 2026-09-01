"""
Repositories package for PostgreSQL database layer.
"""
from database.repositories.student_repository import StudentRepository
from database.repositories.post_repository import PostRepository
from database.repositories.reply_repository import ReplyRepository
from database.repositories.quota_repository import QuotaRepository
from database.repositories.audit_repository import AuditRepository
from database.repositories.settings_repository import SettingsRepository
from database.repositories.admin_repository import AdminRepository

__all__ = [
    "StudentRepository",
    "PostRepository",
    "ReplyRepository",
    "QuotaRepository",
    "AuditRepository",
    "SettingsRepository",
    "AdminRepository",
]
