"""
Admin Repository for PostgreSQL.
Provides persistent storage for individual administrator credentials, active sessions,
security violation events, and login attempts throttling.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, List
from database.connection import DatabasePool


class AdminRepository:
    """مستودع بيانات المشرفين والأمان (Admin Repository)"""

    def __init__(self, pool: DatabasePool):
        self.pool = pool

    async def set_credential(self, telegram_id: int, password_hash: str, role: str) -> None:
        """تعيين أو تحديث كلمة مرور فردية لمشرف محدد"""
        now_dt = datetime.now(timezone.utc)
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO admin_credentials (telegram_id, password_hash, role, created_at)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT(telegram_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role;
            """, telegram_id, password_hash, role, now_dt)

    async def get_credential(self, telegram_id: int) -> Optional[Tuple[str, str]]:
        """جلب هاش كلمة مرور المشرف ودوره: (password_hash, role)"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT password_hash, role FROM admin_credentials WHERE telegram_id = $1;",
                telegram_id
            )
            if row:
                return row["password_hash"], row["role"]
            return None

    async def update_last_login(self, telegram_id: int) -> None:
        """تحديث وقت آخر تسجيل دخول ناجح للمشرف"""
        now_dt = datetime.now(timezone.utc)
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE admin_credentials SET last_login_at = $1 WHERE telegram_id = $2;",
                now_dt, telegram_id
            )

    async def save_session(self, user_id: int, role: str) -> None:
        """حفظ جلسة إدارية نشطة في قاعدة البيانات"""
        now_dt = datetime.now(timezone.utc)
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO admin_sessions (user_id, authenticated_at, role)
                VALUES ($1, $2, $3)
                ON CONFLICT(user_id) DO UPDATE SET authenticated_at = EXCLUDED.authenticated_at, role = EXCLUDED.role;
            """, user_id, now_dt, role)

    async def get_session(self, user_id: int) -> Optional[Tuple[str, str]]:
        """جلب بيانات الجلسة الإدارية النشطة: (authenticated_at_iso, role)"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT authenticated_at, role FROM admin_sessions WHERE user_id = $1;",
                user_id
            )
            if row and row["authenticated_at"]:
                return row["authenticated_at"].isoformat(), row["role"]
            return None

    async def delete_session(self, user_id: int) -> None:
        """إنهاء وإلغاء جلسة إدارية من قاعدة البيانات"""
        async with self.pool.acquire() as conn:
            await conn.execute("DELETE FROM admin_sessions WHERE user_id = $1;", user_id)

    async def record_security_event(self, user_id: int, event_type: str) -> None:
        """تسجيل حدث أمني مع تنظيف تلقائي للأحداث الأقدم من ساعتين"""
        now_dt = datetime.now(timezone.utc)
        cutoff_dt = now_dt - timedelta(hours=2)
        async with self.pool.acquire() as conn:
            await conn.execute("DELETE FROM security_events WHERE created_at < $1;", cutoff_dt)
            await conn.execute("""
                INSERT INTO security_events (user_id, event_type, created_at)
                VALUES ($1, $2, $3);
            """, user_id, event_type, now_dt)

    async def get_recent_security_events_count(self, user_id: int, event_type: str, window_seconds: int) -> int:
        """حساب عدد الأحداث الأمنية لمستخدم خلال نافذة زمنية محددة"""
        since_dt = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        async with self.pool.acquire() as conn:
            count = await conn.fetchval("""
                SELECT COUNT(*) FROM security_events
                WHERE user_id = $1 AND event_type = $2 AND created_at >= $3;
            """, user_id, event_type, since_dt)
            return count or 0

    async def record_login_attempt(self, user_id: int) -> None:
        """تسجيل محاولة دخول إدارية خاطئة"""
        now_dt = datetime.now(timezone.utc)
        cutoff_dt = now_dt - timedelta(hours=2)
        async with self.pool.acquire() as conn:
            await conn.execute("DELETE FROM admin_login_attempts WHERE attempted_at < $1;", cutoff_dt)
            await conn.execute("""
                INSERT INTO admin_login_attempts (user_id, attempted_at)
                VALUES ($1, $2);
            """, user_id, now_dt)

    async def get_recent_login_attempts(self, user_id: int, window_seconds: int) -> List[str]:
        """استرجاع محاولات الدخول الخاطئة للمشرف خلال نافذة زمنية"""
        since_dt = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT attempted_at FROM admin_login_attempts
                WHERE user_id = $1 AND attempted_at >= $2
                ORDER BY attempted_at ASC;
            """, user_id, since_dt)
            return [r["attempted_at"].isoformat() for r in rows if r["attempted_at"]]

    async def clear_login_attempts(self, user_id: int) -> None:
        """مسح محاولات الدخول الخاطئة لمشرف بعد تسجيل دخول ناجح"""
        async with self.pool.acquire() as conn:
            await conn.execute("DELETE FROM admin_login_attempts WHERE user_id = $1;", user_id)
