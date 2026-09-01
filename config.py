"""
Configuration module for the Anonymous Student Telegram Bot.
Validates all environment variables, RBAC definitions, limits, and paths at startup.
"""
import os
from typing import List, Optional, Union, Any
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator, model_validator


class Settings(BaseSettings):
    """
    إعدادات التكوين والبيئة لبوت تيليجرام
    تتحقق من كافة المتغيرات والصلاحيات عند بدء التشغيل دون أي افتراضات غير آمنة
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # توكن البوت الصادر من BotFather
    bot_token: str = Field(..., alias="BOT_TOKEN")

    # معرف القناة الخاصة (معرف رقمي سالب للقنوات الخاصة والمجموعات الخارقة)
    channel_id: int = Field(..., alias="CHANNEL_ID")

    # رابط دعوة القناة الخاصة
    channel_invite_link: str = Field(default="", alias="CHANNEL_INVITE_LINK")

    # معرف المسؤول الأساسي (Primary Admin) - المالك الوحيد لصلاحيات كشف الهوية
    primary_admin_id: Optional[int] = Field(default=None, alias="PRIMARY_ADMIN_ID")

    # قائمة معرفات المشرفين (Moderators) - حظر، كتم، وحذف دون كشف الهوية
    moderator_ids: List[int] = Field(default_factory=list, alias="MODERATOR_IDS")

    # قائمة المشرفين العامة (للتوافق القديم)
    admin_ids_raw: Optional[Union[List[int], str, int]] = Field(default=None, alias="ADMIN_IDS")

    # قناة سجلات المشرفين (اختياري)
    admin_log_channel_id: Optional[int] = Field(default=None, alias="ADMIN_LOG_CHANNEL_ID")

    # تجزئة كلمة مرور الإدارة الآمنة (scrypt hash)
    admin_password_hash: Optional[str] = Field(default=None, alias="ADMIN_PASSWORD_HASH")

    # كلمة المرور الاحتياطية (للتوافق وبيئات الاختبار)
    admin_password: Optional[str] = Field(default=None, alias="ADMIN_PASSWORD")

    # مدة بقاء جلسة المشرف نشطة بالدقائق بعد إدخال كلمة المرور
    admin_session_expiry_minutes: int = Field(default=120, alias="ADMIN_SESSION_EXPIRY_MINUTES")

    # مفتاح التشفير Fernet لقاعدة البيانات (32-byte urlsafe base64)
    encryption_key: str = Field(..., alias="ENCRYPTION_KEY")

    # إعدادات قاعدة بيانات PostgreSQL وسلسلة الاتصال
    database_url: str = Field(
        default="postgresql://postgres:postgres@localhost:5432/anonymous_bot",
        alias="DATABASE_URL"
    )
    database_pool_min: int = Field(default=5, alias="DATABASE_POOL_MIN")
    database_pool_max: int = Field(default=20, alias="DATABASE_POOL_MAX")
    database_command_timeout: float = Field(default=10.0, alias="DATABASE_COMMAND_TIMEOUT")
    database_connect_timeout: float = Field(default=10.0, alias="DATABASE_CONNECT_TIMEOUT")
    database_ssl_mode: Optional[str] = Field(default=None, alias="DATABASE_SSL_MODE")

    # إعدادات مكافحة السبام ومعدل الإرسال
    rate_limit_seconds: int = Field(default=5, alias="RATE_LIMIT_SECONDS")
    max_submissions_per_hour: int = Field(default=20, alias="MAX_SUBMISSIONS_PER_HOUR")

    # حدود الوسائط والملفات
    max_file_size_mb: int = Field(default=20, alias="MAX_FILE_SIZE_MB")
    media_temp_dir: str = Field(default="media_tmp", alias="MEDIA_TEMP_DIR")

    # الفلاتر الرقابية والمحرك المتقدم (Ultra-Strict Moderation Engine)
    moderation_mode: str = Field(default="strict", alias="MODERATION_MODE")
    enable_profanity_filter: bool = Field(default=True, alias="ENABLE_PROFANITY_FILTER")
    allow_links_in_submissions: bool = Field(default=False, alias="ALLOW_LINKS_IN_SUBMISSIONS")
    enable_ocr: bool = Field(default=True, alias="ENABLE_OCR")
    enable_asr: bool = Field(default=False, alias="ENABLE_ASR")
    fail_closed_on_media_error: bool = Field(default=True, alias="FAIL_CLOSED_ON_MEDIA_ANALYSIS_ERROR")
    max_ocr_pages: int = Field(default=20, alias="MAX_OCR_PAGES")
    max_video_frames: int = Field(default=5, alias="MAX_VIDEO_FRAMES")
    max_analysis_seconds: int = Field(default=10, alias="MAX_ANALYSIS_SECONDS")

    # Webhook Settings
    webhook_url: Optional[str] = Field(default=None, alias="WEBHOOK_URL")
    webapp_host: str = Field(default="0.0.0.0", alias="WEBAPP_HOST")
    webapp_port: int = Field(default=8000, alias="WEBAPP_PORT")

    # سياسات حظر الفئات المحددة
    block_profanity: bool = Field(default=True, alias="BLOCK_PROFANITY")
    block_sexual: bool = Field(default=True, alias="BLOCK_SEXUAL")
    block_harassment: bool = Field(default=True, alias="BLOCK_HARASSMENT")
    block_bullying: bool = Field(default=True, alias="BLOCK_BULLYING")
    block_threats: bool = Field(default=True, alias="BLOCK_THREATS")
    block_hate: bool = Field(default=True, alias="BLOCK_HATE")

    @field_validator("webapp_port", mode="before")
    @classmethod
    def parse_webapp_port(cls, v):
        if v is not None and str(v).strip():
            return int(v)
        port_env = os.getenv("PORT")
        if port_env and port_env.strip().isdigit():
            return int(port_env)
        return 8000

    @field_validator("moderator_ids", mode="before")
    @classmethod
    def parse_moderator_ids(cls, v):
        if isinstance(v, str):
            if not v.strip():
                return []
            return [int(x.strip()) for x in v.split(",") if x.strip().lstrip("-").isdigit()]
        if isinstance(v, int):
            return [v]
        return v or []

    @field_validator("admin_log_channel_id", "primary_admin_id", mode="before")
    @classmethod
    def parse_optional_int(cls, v):
        if v is None or v == "" or (isinstance(v, str) and not v.strip()):
            return None
        return int(v)

    @field_validator("encryption_key")
    @classmethod
    def validate_encryption_key(cls, v: str) -> str:
        v_clean = v.strip()
        if not v_clean:
            raise ValueError("مفتاح التشفير ENCRYPTION_KEY لا يمكن أن يكون فارغاً.")
        try:
            from cryptography.fernet import Fernet
            Fernet(v_clean.encode("utf-8"))
        except Exception as e:
            raise ValueError(f"مفتاح التشفير ENCRYPTION_KEY غير صالح (يجب أن يكون 32-byte urlsafe base64): {e}")
        return v_clean

    @field_validator("channel_id")
    @classmethod
    def validate_channel_id(cls, v: int) -> int:
        if v == 0:
            raise ValueError("معرف القناة CHANNEL_ID لا يمكن أن يكون 0.")
        return v

    @model_validator(mode="after")
    def populate_admin_roles(self):
        if self.admin_ids_raw is not None:
            raw_ids = []
            if isinstance(self.admin_ids_raw, str):
                raw_ids = [int(x.strip()) for x in self.admin_ids_raw.split(",") if x.strip().lstrip("-").isdigit()]
            elif isinstance(self.admin_ids_raw, list):
                raw_ids = [int(x) for x in self.admin_ids_raw]
            elif isinstance(self.admin_ids_raw, int):
                raw_ids = [self.admin_ids_raw]

            if raw_ids:
                if self.primary_admin_id is None:
                    self.primary_admin_id = raw_ids[0]
                    other_mods = raw_ids[1:]
                else:
                    other_mods = [x for x in raw_ids if x != self.primary_admin_id]

                for mod_id in other_mods:
                    if mod_id not in self.moderator_ids:
                        self.moderator_ids.append(mod_id)

        # لا نضع كلمة مرور افتراضية معروفة في الكود نهائياً
        # إذا تم تحديد مسؤولين ولم يتم توفير أي تجزئة، يتم تركها None ليتم رفض الدخول ما لم تُعطَ صراحة
        return self

    @property
    def admin_ids(self) -> List[int]:
        """قائمة موحدة لجميع المسؤولين والمشرفين"""
        all_ids = []
        if self.primary_admin_id:
            all_ids.append(self.primary_admin_id)
        for m in self.moderator_ids:
            if m not in all_ids:
                all_ids.append(m)
        return all_ids


def get_settings() -> Settings:
    return Settings()
