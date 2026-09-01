"""
Student Repository for PostgreSQL.
Encapsulates all database operations related to anonymous student accounts,
fingerprint-based bans, mutes, GDPR wipes, and monotonic anonymous ID allocation.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, List, Any
from database.connection import DatabasePool
from database.models import StudentModel
from security.crypto import CryptoManager
from utils.logger import logger


class StudentRepository:
    """مستودع بيانات الطلاب المجهولين (Student Repository)"""

    def __init__(self, pool: DatabasePool):
        self.pool = pool

    def _record_to_student(self, row: Any) -> StudentModel:
        """تحويل سجل PostgreSQL إلى كائن StudentModel المشفر المعزول"""
        return StudentModel(
            id=row["id"],
            anonymous_id=row["anonymous_id"],
            user_hash=row["user_hash"],
            enc_telegram_id=row["enc_telegram_id"],
            enc_full_name=row["enc_full_name"],
            enc_username=row["enc_username"],
            is_banned=bool(row["is_banned"]),
            ban_reason=row["ban_reason"],
            muted_until=row["muted_until"].isoformat() if row["muted_until"] else None,
            total_posts=row["total_posts"],
            total_replies=row["total_replies"],
            created_at=row["created_at"].isoformat() if row["created_at"] else None,
            last_active_at=row["last_active_at"].isoformat() if row["last_active_at"] else None,
            dec_telegram_id=None,
            dec_full_name=None,
            dec_username=None
        )

    async def get_or_create_student(
        self,
        telegram_id: int,
        full_name: Optional[str] = None,
        username: Optional[str] = None,
        crypto: Optional[CryptoManager] = None
    ) -> StudentModel:
        """
        جلب أو إنشاء طالب برقم مجهول تسلسلي دائم وثابت وآمن من الـ Race Conditions
        باستخدام PostgreSQL Sequence (anonymous_student_id_seq) ومعاملة ذرية.
        """
        if crypto is None:
            raise ValueError("يجب توفير CryptoManager لتشفير بيانات الطالب.")

        u_hash = crypto.create_user_hash(telegram_id)
        now_dt = datetime.now(timezone.utc)

        async with self.pool.transaction() as conn:
            # 1. فحص هل بصمة المستخدم مسجلة في سجل الحظر الدائم
            ban_row = await conn.fetchrow(
                "SELECT reason, banned_at FROM banned_fingerprints WHERE id_hash = $1;",
                u_hash
            )
            is_fingerprint_banned = (ban_row is not None)
            fingerprint_reason = ban_row["reason"] if is_fingerprint_banned else None

            # 2. فحص هل الطالب موجود مسبقاً
            row = await conn.fetchrow(
                "SELECT * FROM students WHERE user_hash = $1 FOR UPDATE;",
                u_hash
            )

            if row:
                enc_name = crypto.encrypt(full_name) if full_name else row["enc_full_name"]
                enc_user = crypto.encrypt(username) if username else row["enc_username"]
                is_ban = True if is_fingerprint_banned else row["is_banned"]
                ban_r = fingerprint_reason if is_fingerprint_banned else row["ban_reason"]

                updated_row = await conn.fetchrow("""
                    UPDATE students
                    SET enc_full_name = $1, enc_username = $2, last_active_at = $3,
                        is_banned = $4, ban_reason = $5
                    WHERE user_hash = $6
                    RETURNING *;
                """, enc_name, enc_user, now_dt, is_ban, ban_r, u_hash)

                return self._record_to_student(updated_row)

            # 3. تخصيص ذري للرقم المجهول التالي عبر PostgreSQL Sequence
            next_anon_id = await conn.fetchval("SELECT nextval('anonymous_student_id_seq');")

            enc_tid = crypto.encrypt(telegram_id)
            enc_name = crypto.encrypt(full_name) if full_name else None
            enc_user = crypto.encrypt(username) if username else None

            new_row = await conn.fetchrow("""
                INSERT INTO students (
                    anonymous_id, user_hash, enc_telegram_id,
                    enc_full_name, enc_username, is_banned, ban_reason, created_at, last_active_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING *;
            """, next_anon_id, u_hash, enc_tid, enc_name, enc_user,
                True if is_fingerprint_banned else False,
                fingerprint_reason,
                now_dt, now_dt
            )

            return self._record_to_student(new_row)

    async def get_by_anonymous_id(self, anonymous_id: int) -> Optional[StudentModel]:
        """جلب طالب عبر رقمه المجهول"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM students WHERE anonymous_id = $1;", anonymous_id)
            if row:
                return self._record_to_student(row)
            return None

    async def get_by_user_hash(self, user_hash: str) -> Optional[StudentModel]:
        """جلب طالب عبر الهاش المشفر لمعرف تيليجرام"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM students WHERE user_hash = $1;", user_hash)
            if row:
                return self._record_to_student(row)
            return None

    async def ban_student(self, anonymous_id: int, reason: Optional[str] = None) -> bool:
        """حظر طالب نهائياً من النشر مع حفظ بصمة الحظر الدائمة في جدول منفصل"""
        now_dt = datetime.now(timezone.utc)
        async with self.pool.transaction() as conn:
            row = await conn.fetchrow("SELECT user_hash FROM students WHERE anonymous_id = $1;", anonymous_id)
            if row and row["user_hash"] and not str(row["user_hash"]).startswith("WIPED_"):
                u_hash = row["user_hash"]
                await conn.execute("""
                    INSERT INTO banned_fingerprints (id_hash, reason, banned_at)
                    VALUES ($1, $2, $3)
                    ON CONFLICT(id_hash) DO UPDATE SET reason = EXCLUDED.reason, banned_at = EXCLUDED.banned_at;
                """, u_hash, reason, now_dt)

            result = await conn.execute("""
                UPDATE students
                SET is_banned = TRUE, ban_reason = $1
                WHERE anonymous_id = $2;
            """, reason, anonymous_id)

            return "UPDATE 1" in result

    async def unban_student(self, anonymous_id: int) -> bool:
        """فك حظر طالب وإزالة بصمته من جدول الحظر الدائم"""
        async with self.pool.transaction() as conn:
            row = await conn.fetchrow("SELECT user_hash FROM students WHERE anonymous_id = $1;", anonymous_id)
            if row and row["user_hash"]:
                await conn.execute("DELETE FROM banned_fingerprints WHERE id_hash = $1;", row["user_hash"])

            result = await conn.execute("""
                UPDATE students
                SET is_banned = FALSE, ban_reason = NULL
                WHERE anonymous_id = $1;
            """, anonymous_id)

            return "UPDATE 1" in result

    async def mute_student(self, anonymous_id: int, duration_minutes: int) -> Optional[str]:
        """كتم طالب مؤقتاً لمدة محددة بالدقائق"""
        mute_until = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
        async with self.pool.acquire() as conn:
            result = await conn.execute("""
                UPDATE students
                SET muted_until = $1
                WHERE anonymous_id = $2;
            """, mute_until, anonymous_id)
            if "UPDATE 1" in result:
                return mute_until.isoformat()
            return None

    async def unmute_student(self, anonymous_id: int) -> bool:
        """إلغاء كتم طالب"""
        async with self.pool.acquire() as conn:
            result = await conn.execute("""
                UPDATE students
                SET muted_until = NULL
                WHERE anonymous_id = $1;
            """, anonymous_id)
            return "UPDATE 1" in result

    def is_student_muted(self, student: StudentModel) -> Tuple[bool, Optional[int]]:
        """التحقق هل الطالب مكتوم حالياً؟"""
        if not student.muted_until:
            return False, None
        try:
            mute_dt = datetime.fromisoformat(student.muted_until)
            now_dt = datetime.now(timezone.utc)
            if mute_dt > now_dt:
                remaining_mins = max(1, int((mute_dt - now_dt).total_seconds() / 60))
                return True, remaining_mins
            return False, None
        except Exception:
            return False, None

    async def wipe_student_data(self, anonymous_id: int) -> bool:
        """
        تطهير ومحو بيانات الهوية الشخصية المشفرة للطالب من قاعدة البيانات (GDPR Privacy Wipe)
        مع الحفاظ على الرقم المجهول لسلامة العلاقات التاريخية في القناة.
        """
        async with self.pool.acquire() as conn:
            dummy_hash = f"WIPED_{anonymous_id}_{datetime.now(timezone.utc).timestamp()}"
            result = await conn.execute("""
                UPDATE students
                SET user_hash = $1,
                    enc_telegram_id = '[WIPED]',
                    enc_full_name = '[WIPED]',
                    enc_username = '[WIPED]',
                    is_banned = TRUE,
                    ban_reason = 'تم تطهير البيانات الشخصية بناءً على طلب الخصوصية'
                WHERE anonymous_id = $2;
            """, dummy_hash, anonymous_id)
            return "UPDATE 1" in result

    async def get_all_active_enc_ids(self) -> List[Tuple[str]]:
        """جلب قائمة enc_telegram_id لجميع الطلاب غير المحظورين وغير المطهَّرين"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT enc_telegram_id FROM students WHERE is_banned = FALSE AND enc_telegram_id != '[WIPED]';"
            )
            return [(r["enc_telegram_id"],) for r in rows]
