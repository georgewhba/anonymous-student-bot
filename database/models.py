"""
Data Models for Anonymous Student Telegram Bot.
Defines database entity representations.
Sensitive decrypted identity data is strictly isolated.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class StudentModel:
    """نموذج بيانات الطالب المجهول (آمن وخالٍ من الهوية الصريحة)"""
    id: int
    anonymous_id: int
    user_hash: str
    enc_telegram_id: str
    enc_full_name: Optional[str]
    enc_username: Optional[str]
    is_banned: bool = False
    ban_reason: Optional[str] = None
    muted_until: Optional[str] = None  # ISO timestamp
    total_posts: int = 0
    total_replies: int = 0
    created_at: Optional[str] = None
    last_active_at: Optional[str] = None

    # حقول فك التشفير وقت التشغيل (تبقى None ما لم تُطلب خصيصاً من الـ Primary Admin)
    dec_telegram_id: Optional[int] = None
    dec_full_name: Optional[str] = None
    dec_username: Optional[str] = None


@dataclass
class PostModel:
    """نموذج المنشور الرئيسي في القناة مع حالة المعاملة"""
    id: int
    anonymous_id: int
    channel_message_id: int
    user_msg_id: int
    media_type: str  # text, photo, voice, document, video, audio
    media_file_id: Optional[str]
    content_preview: str
    content_hash: Optional[str]
    created_at: str
    is_deleted: bool = False
    status: str = "published"  # pending, published, failed
    enc_original_filename: Optional[str] = None
    dec_original_filename: Optional[str] = None


@dataclass
class ReplyModel:
    """نموذج الرد المجهول على منشور بالقناة مع حالة المعاملة"""
    id: int
    parent_channel_msg_id: int
    reply_channel_msg_id: int
    anonymous_id: int
    media_type: str
    media_file_id: Optional[str]
    content_preview: str
    created_at: str
    content_hash: Optional[str] = None
    is_deleted: bool = False
    status: str = "published"  # pending, published, failed
    enc_original_filename: Optional[str] = None
    dec_original_filename: Optional[str] = None


@dataclass
class AuditLogModel:
    """نموذج سجل رقابة المشرفين (خالٍ من بيانات PII الحساسة)"""
    id: int
    admin_id: int
    action: str
    target_anonymous_id: Optional[int]
    details: str
    created_at: str
