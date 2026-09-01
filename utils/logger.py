"""
Logging setup module with sensitive PII and credential scrubbing.
"""
import logging
import re
import sys
from typing import Optional
from aiogram import Bot

# أنماط الحماية وتطهير البيانات الحساسة من السجلات
BOT_TOKEN_REGEX = re.compile(r"\b\d{6,12}:[a-zA-Z0-9_-]{20,50}\b")
ENCRYPTION_KEY_REGEX = re.compile(r"(ENCRYPTION_KEY\s*[:=]\s*|key\s*[:=]\s*|EncryptionKey\s*[:=]\s*)([A-Za-z0-9+/=_-]{20,80})", re.IGNORECASE)
PASSWORD_REGEX = re.compile(r"(password\s*[:=]\s*)([^\s,]+)", re.IGNORECASE)
PHONE_REGEX = re.compile(r"\b\+?[0-9]{10,15}\b")
USERNAME_REGEX = re.compile(r"@[a-zA-Z0-9_]{4,32}")
TELEGRAM_ID_REGEX = re.compile(r"\b[1-9]\d{8,10}\b")


def scrub_pii_from_log_message(message: str) -> str:
    """
    تطهير أمني كامل لكافة البيانات الحساسة والشخصية (PII, Tokens, Keys, Passwords, Phones, IDs)
    """
    if not message:
        return ""
    scrubbed = BOT_TOKEN_REGEX.sub("[REDACTED_BOT_TOKEN]", message)
    scrubbed = ENCRYPTION_KEY_REGEX.sub(r"\1[REDACTED_KEY]", scrubbed)
    scrubbed = PASSWORD_REGEX.sub(r"\1[REDACTED_PASSWORD]", scrubbed)
    scrubbed = PHONE_REGEX.sub("[REDACTED_PHONE]", scrubbed)
    scrubbed = USERNAME_REGEX.sub("[REDACTED_USERNAME]", scrubbed)
    scrubbed = TELEGRAM_ID_REGEX.sub("[REDACTED_ID]", scrubbed)
    return scrubbed


class PIIScrubbingFormatter(logging.Formatter):
    """
    مُنسق سجلات أمني يقوم بحجب التوكنات، المفاتيح السرية، وكلمات المرور وهوية الطلاب تلقائياً
    """
    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return scrub_pii_from_log_message(original)


def setup_logger(log_level: int = logging.INFO) -> logging.Logger:
    """إعداد مسجل الأحداث العام مع التطهير الأمني"""
    app_logger = logging.getLogger("anonymous_bot")
    app_logger.setLevel(log_level)

    if not app_logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)

        formatter = PIIScrubbingFormatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        console_handler.setFormatter(formatter)
        app_logger.addHandler(console_handler)

    return app_logger


logger = setup_logger()


async def send_admin_log_notification(
    bot: Bot,
    log_channel_id: Optional[int],
    message_text: str
) -> None:
    """
    إرسال إشعار فوري إلى قناة سجلات المشرفين الإدارية (إن تم ضبطها)
    دون تسريب أي بيانات شخصية (PII-free)
    """
    if not log_channel_id:
        return

    try:
        await bot.send_message(
            chat_id=log_channel_id,
            text=message_text,
            parse_mode="HTML"
        )
    except Exception as e:
        logger.warning(f"تعذر إرسال الإشعار إلى قناة سجلات المشرفين: {e}")
