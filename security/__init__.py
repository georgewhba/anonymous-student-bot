"""
Security and Privacy Layer for Anonymous Student Telegram Bot.
Handles cryptographic operations, authentication, RBAC, identity isolation,
media sanitization, and output escaping.
"""
from security.crypto import CryptoManager
from security.auth import (
    AdminSessionManager,
    admin_session_manager,
    hash_admin_password,
    verify_admin_password,
    AdminRole,
)
from security.identity_vault import IdentityVault, DecryptedIdentity
from security.escaping import escape_user_content, build_channel_post_html, build_channel_reply_html
from security.media_sanitizer import MediaSanitizer

__all__ = [
    "CryptoManager",
    "AdminSessionManager",
    "admin_session_manager",
    "hash_admin_password",
    "verify_admin_password",
    "AdminRole",
    "IdentityVault",
    "DecryptedIdentity",
    "escape_user_content",
    "build_channel_post_html",
    "build_channel_reply_html",
    "MediaSanitizer",
]
