"""
System Settings Repository for PostgreSQL.
Provides configuration storage and global system statistics.
"""
from datetime import datetime, timezone
from typing import Dict, Any
from database.connection import DatabasePool


class SettingsRepository:
    """مستودع إعدادات وإحصائيات النظام (Settings Repository)"""

    def __init__(self, pool: DatabasePool):
        self.pool = pool

    async def get_setting(self, key: str, default: str = "") -> str:
        """قراءة إعداد نظام"""
        async with self.pool.acquire() as conn:
            val = await conn.fetchval("SELECT value FROM system_settings WHERE key = $1;", key)
            if val is not None:
                return val
            return default

    async def set_setting(self, key: str, value: str) -> None:
        """حفظ أو تعديل إعداد نظام"""
        now_dt = datetime.now(timezone.utc)
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO system_settings (key, value, updated_at)
                VALUES ($1, $2, $3)
                ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at;
            """, key, value, now_dt)

    async def get_statistics(self) -> Dict[str, Any]:
        """إحصائيات شاملة للنظام"""
        async with self.pool.acquire() as conn:
            total_students = await conn.fetchval("SELECT COUNT(*) FROM students;")
            total_posts = await conn.fetchval("SELECT COUNT(*) FROM posts WHERE is_deleted = FALSE;")
            total_replies = await conn.fetchval("SELECT COUNT(*) FROM replies WHERE is_deleted = FALSE;")
            banned_students = await conn.fetchval("SELECT COUNT(*) FROM students WHERE is_banned = TRUE;")
            sub_val = await conn.fetchval("SELECT value FROM system_settings WHERE key = 'submissions_enabled';")
            submissions_enabled = (sub_val == "true") if sub_val is not None else True

            return {
                "total_students": total_students or 0,
                "total_posts": total_posts or 0,
                "total_replies": total_replies or 0,
                "banned_students": banned_students or 0,
                "submissions_enabled": submissions_enabled,
            }
