"""
Identity Vault Module.
Enforces cryptographic and authorization barriers between public/anonymous data
and sensitive student identity data (Telegram ID, Real Name, Username).
Decryption is permitted ONLY to the authenticated Primary Admin.
"""
from dataclasses import dataclass
from typing import Optional, Any
from security.crypto import CryptoManager
from security.auth import admin_session_manager


@dataclass
class DecryptedIdentity:
    """بيانات الهوية المفكوكة تشفيرها (حساسة جداً ومحصورة بالمسؤول الأساسي فقط)"""
    anonymous_id: int
    telegram_id: Optional[int]
    full_name: Optional[str]
    username: Optional[str]
    is_banned: bool
    ban_reason: Optional[str]
    muted_until: Optional[str]
    total_posts: int
    total_replies: int
    created_at: Optional[str]
    last_active_at: Optional[str]


class IdentityVault:
    """
    خزنة الهوية المشفرة - تفصل بين البيانات العامة وبيانات الهوية الحساسة
    ولا تسمح لأي خدمة أخرى بفك الهوية مباشرة
    """

    @classmethod
    def resolve(
        cls,
        student: Any,
        crypto: CryptoManager,
        requesting_user_id: int,
        settings: Any
    ) -> DecryptedIdentity:
        """
        كشف هوية الطالب الحقيقية المشفرة.
        متاح حصرياً للمسؤول الأساسي (Primary Admin) مع جلسة نشطة موثقة.
        """
        return cls.resolve_student_identity(student, crypto, requesting_user_id, settings)

    @staticmethod
    def resolve_student_identity(
        student: Any,
        crypto: CryptoManager,
        requesting_user_id: int,
        settings: Any
    ) -> DecryptedIdentity:
        """
        كشف هوية الطالب الحقيقية المشفرة.
        يُسمح فقط للـ Primary Admin بعد التحقق من جلسته النشطة.
        """
        # 1. التحقق من صلاحيات المسؤول الأساسي
        if not admin_session_manager.is_primary_admin(requesting_user_id, settings):
            raise PermissionError("غير مصرح: كشف الهوية المشفرة متاح حصرياً للمسؤول الأساسي (Primary Admin) بجلسة موثقة.")

        # 2. فك التشفير
        dec_tid = crypto.decrypt_int(student.enc_telegram_id)
        dec_name = crypto.decrypt(student.enc_full_name)
        dec_user = crypto.decrypt(student.enc_username)

        return DecryptedIdentity(
            anonymous_id=student.anonymous_id,
            telegram_id=dec_tid,
            full_name=dec_name,
            username=dec_user,
            is_banned=student.is_banned,
            ban_reason=student.ban_reason,
            muted_until=student.muted_until,
            total_posts=student.total_posts,
            total_replies=student.total_replies,
            created_at=student.created_at,
            last_active_at=student.last_active_at
        )

    @staticmethod
    async def send_system_notification(
        bot: Any,
        student: Any,
        crypto: CryptoManager,
        text: str,
        parse_mode: str = "HTML"
    ) -> bool:
        """
        إرسال إشعار نظام/إداري إلى الطالب دون تسريب أو إعادة معرّف التيليجرام لكود المعالجات
        """
        if not student or not student.enc_telegram_id:
            return False
        dec_tid = crypto.decrypt_int(student.enc_telegram_id)
        if not dec_tid:
            return False
        try:
            await bot.send_message(
                chat_id=dec_tid,
                text=text,
                parse_mode=parse_mode
            )
            return True
        except Exception:
            return False

    @staticmethod
    async def send_direct_message(
        bot: Any,
        student: Any,
        crypto: CryptoManager,
        requesting_user_id: int,
        settings: Any,
        text: str,
        parse_mode: str = "HTML",
        reply_markup: Any = None
    ) -> bool:
        """
        إرسال رسالة خاصة مباشرة من الإدارة إلى الطالب (حصرياً للـ Primary Admin)
        """
        if not admin_session_manager.is_primary_admin(requesting_user_id, settings):
            raise PermissionError("غير مصرح: المراسلة المباشرة متاحة حصرياً للمسؤول الأساسي (Primary Admin).")

        if not student or not student.enc_telegram_id:
            return False

        dec_tid = crypto.decrypt_int(student.enc_telegram_id)
        if not dec_tid:
            return False

        try:
            await bot.send_message(
                chat_id=dec_tid,
                text=text,
                parse_mode=parse_mode,
                reply_markup=reply_markup
            )
            return True
        except Exception:
            return False

    @staticmethod
    def decrypt_filename(
        enc_filename: Optional[str],
        crypto: CryptoManager,
        requesting_user_id: int,
        settings: Any
    ) -> Optional[str]:
        """فك تشفير اسم الملف الأصلي المحفوظ حصرياً للمسؤول الأساسي"""
        if not enc_filename:
            return None
        if not admin_session_manager.is_primary_admin(requesting_user_id, settings):
            raise PermissionError("غير مصرح: كشف أسماء الملفات الأصلية متاح حصرياً للمسؤول الأساسي (Primary Admin).")
        return crypto.decrypt(enc_filename)


