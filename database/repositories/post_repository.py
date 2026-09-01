"""
Post Repository for PostgreSQL.
Encapsulates all operations for creating, publishing, finding, and deleting posts.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional, Any
from database.connection import DatabasePool
from database.models import PostModel
from security.crypto import CryptoManager


class PostRepository:
    """مستودع بيانات المنشورات (Post Repository)"""

    def __init__(self, pool: DatabasePool):
        self.pool = pool

    def _record_to_post(self, row: Any) -> PostModel:
        """تحويل سجل PostgreSQL إلى PostModel"""
        return PostModel(
            id=row["id"],
            anonymous_id=row["anonymous_id"],
            channel_message_id=row["channel_message_id"],
            user_msg_id=row["user_msg_id"],
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

    async def create_pending_post(
        self,
        anonymous_id: int,
        user_msg_id: int,
        media_type: str,
        content_preview: str,
        media_file_id: Optional[str] = None,
        content_hash: Optional[str] = None,
        enc_original_filename: Optional[str] = None
    ) -> int:
        """تسجيل معاملة منشور معلق قبل إرسال الرسالة إلى تيليجرام"""
        now_dt = datetime.now(timezone.utc)
        temp_channel_msg_id = -int(now_dt.timestamp() * 1000) % 1000000000
        async with self.pool.acquire() as conn:
            post_id = await conn.fetchval("""
                INSERT INTO posts (
                    anonymous_id, channel_message_id, user_msg_id,
                    media_type, media_file_id, content_preview, content_hash,
                    created_at, enc_original_filename, status
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending')
                RETURNING id;
            """, anonymous_id, temp_channel_msg_id, user_msg_id,
                media_type, media_file_id, content_preview, content_hash,
                now_dt, enc_original_filename
            )
            return post_id

    async def mark_published(
        self,
        post_id: int,
        channel_message_id: int
    ) -> Optional[PostModel]:
        """تحديث المنشور إلى الحالة المنشورة بنجاح وتحديث إحصائيات الطالب ضمن معاملة ذرية"""
        now_dt = datetime.now(timezone.utc)
        async with self.pool.transaction() as conn:
            p_row = await conn.fetchrow("""
                UPDATE posts
                SET channel_message_id = $1, status = 'published'
                WHERE id = $2
                RETURNING *;
            """, channel_message_id, post_id)

            if p_row:
                anon_id = p_row["anonymous_id"]
                await conn.execute("""
                    UPDATE students
                    SET total_posts = total_posts + 1, last_active_at = $1
                    WHERE anonymous_id = $2;
                """, now_dt, anon_id)
                return self._record_to_post(p_row)
            return None

    async def mark_failed(self, post_id: int) -> None:
        """تمييز المنشور كفاشل في قاعدة البيانات"""
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE posts SET is_deleted = TRUE, status = 'failed' WHERE id = $1;",
                post_id
            )

    async def record_post(
        self,
        anonymous_id: int,
        channel_message_id: int,
        user_msg_id: int,
        media_type: str,
        content_preview: str,
        media_file_id: Optional[str] = None,
        content_hash: Optional[str] = None,
        enc_original_filename: Optional[str] = None
    ) -> PostModel:
        """تسجيل منشور جديد مباشرة في القناة وتحديث إحصائيات الطالب"""
        now_dt = datetime.now(timezone.utc)
        async with self.pool.transaction() as conn:
            p_row = await conn.fetchrow("""
                INSERT INTO posts (
                    anonymous_id, channel_message_id, user_msg_id,
                    media_type, media_file_id, content_preview, content_hash,
                    created_at, enc_original_filename, status
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'published')
                RETURNING *;
            """, anonymous_id, channel_message_id, user_msg_id,
                media_type, media_file_id, content_preview, content_hash,
                now_dt, enc_original_filename
            )

            await conn.execute("""
                UPDATE students
                SET total_posts = total_posts + 1, last_active_at = $1
                WHERE anonymous_id = $2;
            """, now_dt, anonymous_id)

            return self._record_to_post(p_row)

    async def get_by_channel_msg_id(self, channel_message_id: int) -> Optional[PostModel]:
        """جلب المنشور عبر معرف رسالة القناة"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM posts WHERE channel_message_id = $1;",
                channel_message_id
            )
            if row:
                return self._record_to_post(row)
            return None

    async def delete_post(self, channel_message_id: int) -> bool:
        """تمييز المنشور كمحذوف"""
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE posts SET is_deleted = TRUE WHERE channel_message_id = $1;",
                channel_message_id
            )
            return "UPDATE 1" in result

    async def check_duplicate_content(self, content_hash: str, since_dt: datetime) -> bool:
        """فحص تطابق المحتوى للمنشورات الحديثة"""
        async with self.pool.acquire() as conn:
            val = await conn.fetchval("""
                SELECT id FROM posts
                WHERE content_hash = $1 AND created_at >= $2
                LIMIT 1;
            """, content_hash, since_dt)
            return val is not None
