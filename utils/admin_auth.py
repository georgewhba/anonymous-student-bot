"""
Admin Auth compatibility module.
Redirects to security.auth.
"""
from security.auth import (
    is_admin_session_valid,
    authenticate_admin_session,
    terminate_admin_session,
    get_lockout_remaining_seconds,
    admin_session_manager,
    AdminRole,
    hash_admin_password,
    verify_admin_password
)

__all__ = [
    "is_admin_session_valid",
    "authenticate_admin_session",
    "terminate_admin_session",
    "get_lockout_remaining_seconds",
    "admin_session_manager",
    "AdminRole",
    "hash_admin_password",
    "verify_admin_password"
]
