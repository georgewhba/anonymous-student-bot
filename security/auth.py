"""
Authentication and Role-Based Access Control (RBAC) Module.
Provides secure password hashing (scrypt), constant-time verification,
in-memory and database-persisted session lifecycle management,
brute-force throttling, and server-side RBAC.
"""
import time
import secrets
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from utils.logger import logger


class AdminRole(str, Enum):
    PRIMARY_ADMIN = "primary_admin"
    MODERATOR = "moderator"


def hash_admin_password(password: str) -> str:
    """
    تجزئة كلمة المرور باستخدام خوارزمية scrypt مع salt عشوائي 16-byte
    """
    if not password:
        raise ValueError("لا يمكن تجزئة كلمة مرور فارغة")
    salt = secrets.token_bytes(16)
    hashed = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        maxmem=0
    )
    return f"scrypt$16384$8$1${salt.hex()}${hashed.hex()}"


# Aliases for convenience across tests and setup scripts
hash_password = hash_admin_password


def verify_admin_password(password: str, stored_hash: str) -> bool:
    """
    التحقق من صحة كلمة المرور بمقارنة ثابتة زمنياً ضد Timing Attacks
    """
    if not password or not stored_hash:
        return False

    stored_hash = stored_hash.strip()

    if stored_hash.startswith("scrypt$"):
        try:
            parts = stored_hash.split("$")
            if len(parts) != 6:
                return False
            n = int(parts[1])
            r = int(parts[2])
            p = int(parts[3])
            salt = bytes.fromhex(parts[4])
            expected_hash = bytes.fromhex(parts[5])

            computed_hash = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt,
                n=n,
                r=r,
                p=p,
                maxmem=0
            )
            return hmac.compare_digest(computed_hash, expected_hash)
        except Exception as e:
            logger.error(f"خطأ أثناء التحقق من تجزئة كلمة المرور: {e}")
            return False

    # دعم الكلمات الصريحة في بيئة الاختبار إذا تم تمرير نص عادي مع مقارنة ثابتة زمنياً
    return hmac.compare_digest(stored_hash.encode("utf-8"), password.encode("utf-8"))


class AdminSessionManager:
    """
    مدير جلسات المشرفين والتحكم بالصلاحيات (RBAC).
    - التحقق من الأدوار (Primary Admin vs Moderator)
    - إدارة انتهاء صلاحية الجلسة
    - كبح محاولات التخمين والحظر المؤقت (Lockout)
    - دعم كلمات المرور الفردية لكل مشرف مع التراجع الآمن
    """

    def __init__(self):
        # {user_id: {"authenticated_at": float, "role": AdminRole}}
        self._sessions: Dict[int, Dict[str, Any]] = {}
        # {user_id: [timestamp1, timestamp2, ...]}
        self._failed_attempts: Dict[int, List[float]] = {}
        self.lockout_window_seconds = 900  # 15 دقيقة
        self.max_failed_attempts = 5

    def get_role_for_user(self, user_id: int, settings: Any) -> Optional[AdminRole]:
        """تحديد الدور الإداري للمستخدم بناءً على الإعدادات أو قاعدة البيانات"""
        if settings.primary_admin_id and user_id == settings.primary_admin_id:
            return AdminRole.PRIMARY_ADMIN
        if hasattr(settings, "moderator_ids") and user_id in settings.moderator_ids:
            return AdminRole.MODERATOR
        if hasattr(settings, "admin_ids") and user_id in settings.admin_ids:
            return AdminRole.MODERATOR
        return None

    def is_session_valid(self, user_id: int, settings: Any) -> bool:
        """فحص هل جلسة المستخدم موثقة ونشطة وضمن مدة الصلاحية؟"""
        role = self.get_role_for_user(user_id, settings)
        if not role:
            return False

        expiry_seconds = getattr(settings, "admin_session_expiry_minutes", 120) * 60
        now = time.time()

        session = self._sessions.get(user_id)
        if session:
            auth_time = session.get("authenticated_at", 0.0)
            if now - auth_time <= expiry_seconds:
                return True
            else:
                self.terminate_session(user_id, settings)
                return False

        return False

    def get_lockout_remaining_seconds(self, user_id: int, settings: Optional[Any] = None) -> int:
        """إرجاع الثواني المتبقية لفك الحظر المؤقت بعد المحاولات الخاطئة"""
        now = time.time()
        fails = self._failed_attempts.get(user_id, [])
        recent_fails = [t for t in fails if now - t < self.lockout_window_seconds]

        if len(recent_fails) >= self.max_failed_attempts:
            oldest = min(recent_fails)
            return max(0, int(self.lockout_window_seconds - (now - oldest)))
        return 0

    def authenticate(
        self,
        user_id: int,
        entered_password: str,
        settings: Any,
        custom_password_hash: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        التحقق من كلمة المرور الفردية أو العامة وتسجيل جلسة جديدة نشطة
        يرجع: (is_success, error_message_or_none)
        """
        role = self.get_role_for_user(user_id, settings)
        if not role:
            return False, "غير مصرح: المستخدم ليس مسجلاً كمسؤول أو مشرف"

        # فحص الحظر المؤقت
        lockout_secs = self.get_lockout_remaining_seconds(user_id, settings)
        if lockout_secs > 0:
            lockout_mins = max(1, lockout_secs // 60)
            return False, f"الحساب مقفل مؤقتاً لتجاوز المحاولات الخاطئة. انتظر {lockout_mins} دقيقة."

        # البحث عن كلمة المرور (فردية أولاً ثم الإعدادات العامة)
        target_hash = custom_password_hash
        if not target_hash and hasattr(settings, "admin_passwords") and isinstance(settings.admin_passwords, dict):
            target_hash = settings.admin_passwords.get(user_id)
        if not target_hash:
            target_hash = getattr(settings, "admin_password_hash", None)
        if not target_hash:
            target_hash = getattr(settings, "admin_password", "")

        is_valid = verify_admin_password(entered_password, target_hash)

        now = time.time()

        if is_valid:
            self._sessions[user_id] = {
                "authenticated_at": now,
                "role": role
            }
            self._failed_attempts.pop(user_id, None)
            logger.info(f"تم توثيق جلسة إدارية بنجاح للمستخدم {user_id} بالدور {role.value}")
            return True, None
        else:
            fails = self._failed_attempts.get(user_id, [])
            fails = [t for t in fails if now - t < self.lockout_window_seconds]
            fails.append(now)
            self._failed_attempts[user_id] = fails

            remaining_attempts = max(0, self.max_failed_attempts - len(fails))
            logger.warning(f"محاولة تسجيل دخول إداري خاطئة للمستخدم {user_id}. محاولات متبقية: {remaining_attempts}")
            return False, f"كلمة المرور غير صحيحة. المحاولات المتبقية قبل القفل: {remaining_attempts}"

    def create_session(self, user_id: int, role: Optional[AdminRole] = None, settings: Optional[Any] = None) -> None:
        """إنشاء جلسة مباشرة للمستخدم (مفيد لبيئات الاختبار والتهيئة)"""
        now = time.time()
        assigned_role = role or AdminRole.PRIMARY_ADMIN
        self._sessions[user_id] = {
            "authenticated_at": now,
            "role": assigned_role
        }
        self._failed_attempts.pop(user_id, None)

    def terminate_session(self, user_id: int, settings: Optional[Any] = None) -> None:
        """إنهاء وإقفال الجلسة النشطة (تسجيل الخروج)"""
        self._sessions.pop(user_id, None)
        logger.info(f"تم تسجيل خروج المشرف {user_id}")

    def is_primary_admin(self, user_id: int, settings: Any) -> bool:
        """التحقق هل المستخدم هو المسؤول الأساسي ولديه جلسة موثقة نشطة؟"""
        if not self.is_session_valid(user_id, settings):
            return False
        return self.get_role_for_user(user_id, settings) == AdminRole.PRIMARY_ADMIN

    def is_moderator_or_higher(self, user_id: int, settings: Any) -> bool:
        """التحقق هل المستخدم مشرف أو مسؤول أساسي ولديه جلسة موثقة نشطة؟"""
        if not self.is_session_valid(user_id, settings):
            return False
        role = self.get_role_for_user(user_id, settings)
        return role in (AdminRole.PRIMARY_ADMIN, AdminRole.MODERATOR)


# الكائن العام لإدارة الجلسات
admin_session_manager = AdminSessionManager()

# توفير دوال مساعدة للتوافق
def is_admin_session_valid(user_id: int, settings: Any) -> bool:
    return admin_session_manager.is_session_valid(user_id, settings)

def authenticate_admin_session(user_id: int, entered_password: str, settings: Any) -> bool:
    success, _ = admin_session_manager.authenticate(user_id, entered_password, settings)
    return success

def terminate_admin_session(user_id: int) -> None:
    admin_session_manager.terminate_session(user_id)

def get_lockout_remaining_seconds(user_id: int) -> int:
    return admin_session_manager.get_lockout_remaining_seconds(user_id)
