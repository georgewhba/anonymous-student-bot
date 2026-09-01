"""
PostgreSQL Database Manager and Facade Layer.
Coordinates repositories, connection lifecycle, and transaction management
for the Anonymous Student Telegram Bot.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple

from security.crypto import CryptoManager
from database.connection import DatabasePool
from database.models import StudentModel, PostModel, ReplyModel, AuditLogModel
from database.repositories.student_repository import StudentRepository
from database.repositories.post_repository import PostRepository
from database.repositories.reply_repository import ReplyRepository
from database.repositories.quota_repository import QuotaRepository
from database.repositories.audit_repository import AuditRepository
from database.repositories.settings_repository import SettingsRepository
from database.repositories.admin_repository import AdminRepository
from utils.logger import logger


SCHEMA_SQL = """
-- Sequence for atomic, monotonic, race-free anonymous ID allocation
CREATE SEQUENCE IF NOT EXISTS anonymous_student_id_seq START WITH 101 INCREMENT BY 1 NO CYCLE;

-- Students table
CREATE TABLE IF NOT EXISTS students (
    id SERIAL PRIMARY KEY,
    anonymous_id INTEGER UNIQUE NOT NULL,
    user_hash VARCHAR(64) UNIQUE NOT NULL,
    enc_telegram_id TEXT NOT NULL,
    enc_full_name TEXT,
    enc_username TEXT,
    is_banned BOOLEAN NOT NULL DEFAULT FALSE,
    ban_reason TEXT,
    muted_until TIMESTAMPTZ,
    total_posts INTEGER NOT NULL DEFAULT 0,
    total_replies INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Permanent banned fingerprints
CREATE TABLE IF NOT EXISTS banned_fingerprints (
    id_hash VARCHAR(64) PRIMARY KEY,
    reason TEXT,
    banned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Individual Admin credentials
CREATE TABLE IF NOT EXISTS admin_credentials (
    telegram_id BIGINT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

-- Security events log
CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Admin login attempts for lockout
CREATE TABLE IF NOT EXISTS admin_login_attempts (
    id SERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Persistent admin sessions
CREATE TABLE IF NOT EXISTS admin_sessions (
    user_id BIGINT PRIMARY KEY,
    authenticated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    role VARCHAR(32) NOT NULL
);

-- Channel posts
CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    anonymous_id INTEGER NOT NULL REFERENCES students(anonymous_id) ON DELETE RESTRICT,
    channel_message_id BIGINT UNIQUE NOT NULL,
    user_msg_id BIGINT NOT NULL,
    media_type VARCHAR(32) NOT NULL,
    media_file_id TEXT,
    content_preview TEXT,
    content_hash VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(32) NOT NULL DEFAULT 'published',
    enc_original_filename TEXT
);

-- Channel replies
CREATE TABLE IF NOT EXISTS replies (
    id SERIAL PRIMARY KEY,
    parent_channel_msg_id BIGINT NOT NULL,
    reply_channel_msg_id BIGINT UNIQUE NOT NULL,
    anonymous_id INTEGER NOT NULL REFERENCES students(anonymous_id) ON DELETE RESTRICT,
    media_type VARCHAR(32) NOT NULL,
    media_file_id TEXT,
    content_preview TEXT,
    content_hash VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(32) NOT NULL DEFAULT 'published',
    enc_original_filename TEXT
);

-- Hourly submission quotas
CREATE TABLE IF NOT EXISTS submission_quotas (
    user_hash VARCHAR(64) NOT NULL,
    window_hour VARCHAR(32) NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (user_hash, window_hour)
);

-- Audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    admin_id BIGINT NOT NULL,
    action VARCHAR(64) NOT NULL,
    target_anonymous_id INTEGER,
    details TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- System settings
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(64) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_students_hash ON students(user_hash);
CREATE INDEX IF NOT EXISTS idx_students_anon ON students(anonymous_id);
CREATE INDEX IF NOT EXISTS idx_posts_channel_msg ON posts(channel_message_id);
CREATE INDEX IF NOT EXISTS idx_posts_hash_created ON posts(content_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_replies_parent ON replies(parent_channel_msg_id);
CREATE INDEX IF NOT EXISTS idx_replies_msg ON replies(reply_channel_msg_id);
CREATE INDEX IF NOT EXISTS idx_replies_hash_created ON replies(content_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_quotas_window ON submission_quotas(window_hour);
CREATE INDEX IF NOT EXISTS idx_security_events_lookup ON security_events(user_id, event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_admin_login_attempts_lookup ON admin_login_attempts(user_id, attempted_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);
"""


class DatabaseManager:
    """
    مدير قاعدة البيانات غير المتزامن (Async PostgreSQL Manager & Facade)
    يدير تخزين واسترجاع بيانات الطلاب والمنشورات والردود وسجل المشرفين
    مع تشفير كامل لبيانات الهوية الشخصية وتخصيص ذري للأرقام المجهولة عبر PostgreSQL.
    """

    def __init__(
        self,
        db_url: str,
        crypto: CryptoManager,
        pool_min: int = 5,
        pool_max: int = 20,
        command_timeout: float = 10.0,
        connect_timeout: float = 10.0,
        ssl_mode: Optional[str] = None
    ):
        self.db_url = db_url
        self.crypto = crypto

        self.pool = DatabasePool(
            dsn=db_url,
            min_size=pool_min,
            max_size=pool_max,
            command_timeout=command_timeout,
            connect_timeout=connect_timeout,
            ssl_mode=ssl_mode
        )

        # تهيئة المستودعات
        self.students = StudentRepository(self.pool)
        self.posts = PostRepository(self.pool)
        self.replies = ReplyRepository(self.pool)
        self.quotas = QuotaRepository(self.pool)
        self.audit = AuditRepository(self.pool)
        self.settings = SettingsRepository(self.pool)
        self.admins = AdminRepository(self.pool)

    async def init_db(self) -> None:
        """تهيئة مجمع الاتصالات وبناء المخطط الأولي إذا لم يكن موجوداً"""
        await self.pool.initialize()

        async with self.pool.acquire() as conn:
            # تنفيذ مخطط الجداول والفهارس
            await conn.execute(SCHEMA_SQL)

            # ضبط القيمة الافتراضية لإعدادات النشر
            await conn.execute("""
                INSERT INTO system_settings (key, value, updated_at)
                VALUES ('submissions_enabled', 'true', NOW())
                ON CONFLICT (key) DO NOTHING;
            """)

        logger.info("✅ تم تهيئة والتحقق من مخطط قاعدة بيانات PostgreSQL بنجاح.")

    async def close(self) -> None:
        """إغلاق مجمع الاتصالات بأمان"""
        await self.pool.close()

    # =========================================================================
    # دوال الطلاب والأرقام المجهولة (Students Facade)
    # =========================================================================

    async def get_or_create_student(
        self,
        telegram_id: int,
        full_name: Optional[str] = None,
        username: Optional[str] = None
    ) -> StudentModel:
        return await self.students.get_or_create_student(
            telegram_id=telegram_id,
            full_name=full_name,
            username=username,
            crypto=self.crypto
        )

    async def get_student_by_anonymous_id(self, anonymous_id: int) -> Optional[StudentModel]:
        return await self.students.get_by_anonymous_id(anonymous_id)

    async def get_public_student_by_anonymous_id(self, anonymous_id: int) -> Optional[StudentModel]:
        return await self.students.get_by_anonymous_id(anonymous_id)

    async def get_student_by_telegram_id(self, telegram_id: int) -> Optional[StudentModel]:
        u_hash = self.crypto.create_user_hash(telegram_id)
        return await self.students.get_by_user_hash(u_hash)

    async def get_public_student_by_telegram_id(self, telegram_id: int) -> Optional[StudentModel]:
        return await self.get_student_by_telegram_id(telegram_id)

    async def ban_student(self, anonymous_id: int, reason: Optional[str] = None) -> bool:
        return await self.students.ban_student(anonymous_id, reason)

    async def unban_student(self, anonymous_id: int) -> bool:
        return await self.students.unban_student(anonymous_id)

    async def mute_student(self, anonymous_id: int, duration_minutes: int) -> Optional[str]:
        return await self.students.mute_student(anonymous_id, duration_minutes)

    async def unmute_student(self, anonymous_id: int) -> bool:
        return await self.students.unmute_student(anonymous_id)

    def is_student_muted(self, student: StudentModel) -> Tuple[bool, Optional[int]]:
        return self.students.is_student_muted(student)

    async def wipe_student_data(self, anonymous_id: int) -> bool:
        return await self.students.wipe_student_data(anonymous_id)

    async def get_all_active_student_enc_ids(self) -> List[Tuple[str]]:
        return await self.students.get_all_active_enc_ids()

    # =========================================================================
    # دوال المنشورات (Posts Facade)
    # =========================================================================

    async def create_pending_post(
        self,
        anonymous_id: int,
        user_msg_id: int,
        media_type: str,
        content_preview: str,
        media_file_id: Optional[str] = None,
        content_hash: Optional[str] = None,
        original_filename: Optional[str] = None
    ) -> int:
        enc_orig_fn = self.crypto.encrypt(original_filename) if original_filename else None
        return await self.posts.create_pending_post(
            anonymous_id=anonymous_id,
            user_msg_id=user_msg_id,
            media_type=media_type,
            content_preview=content_preview,
            media_file_id=media_file_id,
            content_hash=content_hash,
            enc_original_filename=enc_orig_fn
        )

    async def mark_post_published(
        self,
        post_id: int,
        channel_message_id: int
    ) -> Optional[PostModel]:
        return await self.posts.mark_published(post_id, channel_message_id)

    async def mark_post_failed(self, post_id: int) -> None:
        await self.posts.mark_failed(post_id)

    async def record_post(
        self,
        anonymous_id: int,
        channel_message_id: int,
        user_msg_id: int,
        media_type: str,
        content_preview: str,
        media_file_id: Optional[str] = None,
        content_hash: Optional[str] = None,
        original_filename: Optional[str] = None
    ) -> PostModel:
        enc_orig_fn = self.crypto.encrypt(original_filename) if original_filename else None
        return await self.posts.record_post(
            anonymous_id=anonymous_id,
            channel_message_id=channel_message_id,
            user_msg_id=user_msg_id,
            media_type=media_type,
            content_preview=content_preview,
            media_file_id=media_file_id,
            content_hash=content_hash,
            enc_original_filename=enc_orig_fn
        )

    async def get_post_by_channel_msg_id(self, channel_message_id: int) -> Optional[PostModel]:
        return await self.posts.get_by_channel_msg_id(channel_message_id)

    # =========================================================================
    # دوال الردود (Replies Facade)
    # =========================================================================

    async def create_pending_reply(
        self,
        parent_channel_msg_id: int,
        anonymous_id: int,
        media_type: str,
        content_preview: str,
        media_file_id: Optional[str] = None,
        content_hash: Optional[str] = None,
        original_filename: Optional[str] = None
    ) -> int:
        enc_orig_fn = self.crypto.encrypt(original_filename) if original_filename else None
        return await self.replies.create_pending_reply(
            parent_channel_msg_id=parent_channel_msg_id,
            anonymous_id=anonymous_id,
            media_type=media_type,
            content_preview=content_preview,
            media_file_id=media_file_id,
            content_hash=content_hash,
            enc_original_filename=enc_orig_fn
        )

    async def mark_reply_published(
        self,
        reply_id: int,
        reply_channel_msg_id: int
    ) -> Optional[ReplyModel]:
        return await self.replies.mark_published(reply_id, reply_channel_msg_id)

    async def mark_reply_failed(self, reply_id: int) -> None:
        await self.replies.mark_failed(reply_id)

    async def record_reply(
        self,
        parent_channel_msg_id: int,
        reply_channel_msg_id: int,
        anonymous_id: int,
        media_type: str,
        content_preview: str,
        media_file_id: Optional[str] = None,
        content_hash: Optional[str] = None,
        original_filename: Optional[str] = None
    ) -> ReplyModel:
        enc_orig_fn = self.crypto.encrypt(original_filename) if original_filename else None
        return await self.replies.record_reply(
            parent_channel_msg_id=parent_channel_msg_id,
            reply_channel_msg_id=reply_channel_msg_id,
            anonymous_id=anonymous_id,
            media_type=media_type,
            content_preview=content_preview,
            media_file_id=media_file_id,
            content_hash=content_hash,
            enc_original_filename=enc_orig_fn
        )

    async def get_reply_by_channel_msg_id(self, channel_message_id: int) -> Optional[ReplyModel]:
        return await self.replies.get_by_channel_msg_id(channel_message_id)

    # =========================================================================
    # البحث الموحد والحذف وفحص التكرار (General Operations)
    # =========================================================================

    async def find_author_by_channel_message_id(
        self,
        channel_message_id: int
    ) -> Optional[Tuple[StudentModel, str, str]]:
        post = await self.get_post_by_channel_msg_id(channel_message_id)
        if post:
            student = await self.get_student_by_anonymous_id(post.anonymous_id)
            if student:
                return student, f"منشور رئيسي #{channel_message_id}", post.content_preview

        reply = await self.get_reply_by_channel_msg_id(channel_message_id)
        if reply:
            student = await self.get_student_by_anonymous_id(reply.anonymous_id)
            if student:
                return student, f"رد على المنشور #{reply.parent_channel_msg_id}", reply.content_preview

        return None

    async def delete_post_from_db(self, channel_message_id: int) -> bool:
        deleted_post = await self.posts.delete_post(channel_message_id)
        deleted_reply = await self.replies.delete_reply(channel_message_id)
        return deleted_post or deleted_reply

    async def check_duplicate_content(
        self,
        content_hash: str,
        within_seconds: int = 300
    ) -> bool:
        if not content_hash:
            return False
        since_dt = datetime.now(timezone.utc) - timedelta(seconds=within_seconds)
        if await self.posts.check_duplicate_content(content_hash, since_dt):
            return True
        return await self.replies.check_duplicate_content(content_hash, since_dt)

    async def check_and_increment_hourly_quota(
        self,
        telegram_id: int,
        max_submissions_per_hour: int
    ) -> Tuple[bool, int]:
        u_hash = self.crypto.create_user_hash(telegram_id)
        return await self.quotas.check_and_increment_hourly_quota(
            user_hash=u_hash,
            max_submissions_per_hour=max_submissions_per_hour
        )

    # =========================================================================
    # دوال سجل الرقابة والإعدادات (Audit & Settings)
    # =========================================================================

    async def log_audit_action(
        self,
        admin_id: int,
        action: str,
        details: str,
        target_anonymous_id: Optional[int] = None
    ) -> None:
        await self.audit.log_action(admin_id, action, details, target_anonymous_id)

    async def get_recent_audit_logs(self, limit: int = 15) -> List[AuditLogModel]:
        return await self.audit.get_recent(limit=limit)

    async def get_system_setting(self, key: str, default: str = "") -> str:
        return await self.settings.get_setting(key, default)

    async def set_system_setting(self, key: str, value: str) -> None:
        await self.settings.set_setting(key, value)

    async def get_statistics(self) -> Dict[str, Any]:
        return await self.settings.get_statistics()

    # =========================================================================
    # دوال إدارة بيانات المشرفين والأمان (Admin & Security)
    # =========================================================================

    async def set_admin_credential(self, telegram_id: int, password_hash: str, role: str) -> None:
        await self.admins.set_credential(telegram_id, password_hash, role)

    async def get_admin_credential(self, telegram_id: int) -> Optional[Tuple[str, str]]:
        return await self.admins.get_credential(telegram_id)

    async def update_admin_last_login(self, telegram_id: int) -> None:
        await self.admins.update_last_login(telegram_id)

    async def save_admin_session(self, user_id: int, role: str) -> None:
        await self.admins.save_session(user_id, role)

    async def get_admin_session(self, user_id: int) -> Optional[Tuple[str, str]]:
        return await self.admins.get_session(user_id)

    async def delete_admin_session(self, user_id: int) -> None:
        await self.admins.delete_session(user_id)

    async def record_security_event(self, user_id: int, event_type: str, details: Optional[str] = None) -> None:
        await self.admins.record_security_event(user_id, event_type)

    async def get_recent_security_events_count(self, user_id: int, event_type: str, window_seconds: int) -> int:
        return await self.admins.get_recent_security_events_count(user_id, event_type, window_seconds)

    async def record_admin_login_attempt(self, user_id: int) -> None:
        await self.admins.record_login_attempt(user_id)

    async def get_recent_admin_login_attempts(self, user_id: int, window_seconds: int) -> List[str]:
        return await self.admins.get_recent_login_attempts(user_id, window_seconds)

    async def clear_admin_login_attempts(self, user_id: int) -> None:
        await self.admins.clear_login_attempts(user_id)
