"""
Reply Repository for PostgreSQL.
Encapsulates all operations for creating, publishing, finding, and deleting replies.
"""
from datetime import datetime, timezone
from typing import Optional, Any
from database.connection import DatabasePool
from database.models import ReplyModel


class ReplyRepository:
    """مستودع بيانات الردود (Reply Repository)"""

    def __init__(self, pool: DatabasePool):
        self.pool = pool

    def _record_to_reply(self, row: Any) -> ReplyModel:
        """تحويل سجل PostgreSQL إلى ReplyModel"""
        return ReplyModel(
            id=row["id"],
            parent_channel_msg_id=row["parent_channel_msg_id"],
            reply_channel_msg_id=row["reply_channel_msg_id"],
            anonymous_id=row["anonymous_id"],
            media_type=row["media_type"],
            media_file_id=row["media_file_id"],
            content_preview=row["content_preview"],
            content_hash=row["content_hash"],
            created_at=row["created_at"].isoformat() if row["created_at"] else "",
            is_deleted=bool(row["is_deleted"]),
            status=row.get("status", "published"),
            enc_original_filename=row.get("enc_original_filename"),
            dec_original_filename=None
        )

    async def create_pending_reply(
        self,
        parent_channel_msg_id: int,
        anonymous_id: int,
        media_type: str,
        content_preview: str,
        media_file_id: Optional[str] = None,
        content_hash: Optional[str] = None,
        enc_original_filename: Optional[str] = None
    ) -> int:
        """تسجيل معاملة رد معلق قبل إرسال الرسالة إلى تيليجرام"""
        now_dt = datetime.now(timezone.utc)
        temp_reply_msg_id = -int(now_dt.timestamp() * 1000) % 1000000000
        async with self.pool.acquire() as conn:
            reply_id = await conn.fetchval("""
                INSERT INTO replies (
                    parent_channel_msg_id, reply_channel_msg_id,
                    anonymous_id, media_type, media_file_id, content_preview, content_hash,
                    created_at, enc_original_filename, status
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending')
                RETURNING id;
            """, parent_channel_msg_id, temp_reply_msg_id,
                anonymous_id, media_type, media_file_id, content_preview, content_hash,
                now_dt, enc_original_filename
            )
            return reply_id

    async def mark_published(
        self,
        reply_id: int,
        reply_channel_msg_id: int
    ) -> Optional[ReplyModel]:
        """تحديث الرد إلى الحالة المنشورة بنجاح وتحديث إحصائيات الطالب ضمن معاملة ذرية"""
        now_dt = datetime.now(timezone.utc)
        async with self.pool.transaction() as conn:
            r_row = await conn.fetchrow("""
                UPDATE replies
                SET reply_channel_msg_id = $1, status = 'published'
                WHERE id = $2
                RETURNING *;
            """, reply_channel_msg_id, reply_id)

            if r_row:
                anon_id = r_row["anonymous_id"]
                await conn.execute("""
                    UPDATE students
                    SET total_replies = total_replies + 1, last_active_at = $1
                    WHERE anonymous_id = $2;
                """, now_dt, anon_id)
                return self._record_to_reply(r_row)
            return None

    async def mark_failed(self, reply_id: int) -> None:
        """تمييز الرد كفاشل في قاعدة البيانات"""
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE replies SET is_deleted = TRUE, status = 'failed' WHERE id = $1;",
                reply_id
            )

    async def record_reply(
        self,
        parent_channel_msg_id: int,
        reply_channel_msg_id: int,
        anonymous_id: int,
        media_type: str,
        content_preview: str,
        media_file_id: Optional[str] = None,
        content_hash: Optional[str] = None,
        enc_original_filename: Optional[str] = None
    ) -> ReplyModel:
        """تسجيل رد مجهول مباشرة في القناة وتحديث إحصائيات الطالب"""
        now_dt = datetime.now(timezone.utc)
        async with self.pool.transaction() as conn:
            r_row = await conn.fetchrow("""
                INSERT INTO replies (
                    parent_channel_msg_id, reply_channel_msg_id,
                    anonymous_id, media_type, media_file_id, content_preview, content_hash,
                    created_at, enc_original_filename, status
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'published')
                RETURNING *;
            """, parent_channel_msg_id, reply_channel_msg_id,
                anonymous_id, media_type, media_file_id, content_preview, content_hash,
                now_dt, enc_original_filename
            )

            await conn.execute("""
                UPDATE students
                SET total_replies = total_replies + 1, last_active_at = $1
                WHERE anonymous_id = $2;
            """, now_dt, anonymous_id)

            return self._record_to_reply(r_row)

    async def get_by_channel_msg_id(self, channel_message_id: int) -> Optional[ReplyModel]:
        """جلب الرد عبر معرف رسالة القناة"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM replies WHERE reply_channel_msg_id = $1;",
                channel_message_id
            )
            if row:
                return self._record_to_reply(row)
            return None

    async def delete_reply(self, channel_message_id: int) -> bool:
        """تمييز الرد كمحذوف"""
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE replies SET is_deleted = TRUE WHERE reply_channel_msg_id = $1;",
                channel_message_id
            )
            return "UPDATE 1" in result

    async def check_duplicate_content(self, content_hash: str, since_dt: datetime) -> bool:
        """فحص تطابق المحتوى للردود الحديثة"""
        async with self.pool.acquire() as conn:
            val = await conn.fetchval("""
                SELECT id FROM replies
                WHERE content_hash = $1 AND created_at >= $2
                LIMIT 1;
            """, content_hash, since_dt)
            return val is not None
