"""
Submission Quota Repository for PostgreSQL.
Provides persistent, concurrency-safe, race-condition-free hourly submission quotas
using row-level locking (FOR UPDATE) and atomic transactions.
"""
from datetime import datetime, timezone, timedelta
from typing import Tuple
from database.connection import DatabasePool


class QuotaRepository:
    """مستودع الحصص ومعدلات الإرسال (Rate Limit Quota Repository)"""

    def __init__(self, pool: DatabasePool):
        self.pool = pool

    async def check_and_increment_hourly_quota(
        self,
        user_hash: str,
        max_submissions_per_hour: int
    ) -> Tuple[bool, int]:
        """
        فحص وزيادة الحصة الساعية المستمرة في قاعدة البيانات بطريقة ذرية وآمنة من التزامن.
        يرجع: (is_allowed, current_count)
        """
        now = datetime.now(timezone.utc)
        current_window = now.strftime("%Y-%m-%d_%H")
        old_cutoff = (now - timedelta(hours=3)).strftime("%Y-%m-%d_%H")

        async with self.pool.transaction() as conn:
            # تنظيف النوافذ القديمة تلقائياً
            await conn.execute("DELETE FROM submission_quotas WHERE window_hour < $1;", old_cutoff)

            # محاولة جلب السجل الحالي مع قفل الصف (Row-level Lock)
            row = await conn.fetchrow(
                "SELECT count FROM submission_quotas WHERE user_hash = $1 AND window_hour = $2 FOR UPDATE;",
                user_hash, current_window
            )

            if row:
                current_count = row["count"]
                if current_count >= max_submissions_per_hour:
                    return False, current_count

                new_count = current_count + 1
                await conn.execute(
                    "UPDATE submission_quotas SET count = $1 WHERE user_hash = $2 AND window_hour = $3;",
                    new_count, user_hash, current_window
                )
                return True, new_count
            else:
                # إدراج جديد للحصة
                await conn.execute(
                    "INSERT INTO submission_quotas (user_hash, window_hour, count) VALUES ($1, $2, 1);",
                    user_hash, current_window
                )
                return True, 1
