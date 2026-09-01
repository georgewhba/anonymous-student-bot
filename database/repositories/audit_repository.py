"""
Audit Log Repository for PostgreSQL.
Provides secure, PII-free administrative action logging and retrieval with pagination.
"""
from datetime import datetime, timezone
from typing import List, Optional, Any
from database.connection import DatabasePool
from database.models import AuditLogModel


class AuditRepository:
    """مستودع سجل الرقابة والتدقيق (Audit Log Repository)"""

    def __init__(self, pool: DatabasePool):
        self.pool = pool

    def _record_to_audit(self, row: Any) -> AuditLogModel:
        """تحويل سجل PostgreSQL إلى AuditLogModel"""
        return AuditLogModel(
            id=row["id"],
            admin_id=row["admin_id"],
            action=row["action"],
            target_anonymous_id=row["target_anonymous_id"],
            details=row["details"],
            created_at=row["created_at"].isoformat() if row["created_at"] else ""
        )

    async def log_action(
        self,
        admin_id: int,
        action: str,
        details: str,
        target_anonymous_id: Optional[int] = None
    ) -> None:
        """تسجيل إجراء إداري في سجل الرقابة بدون تسريب بيانات PII"""
        now_dt = datetime.now(timezone.utc)
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO audit_logs (admin_id, action, target_anonymous_id, details, created_at)
                VALUES ($1, $2, $3, $4, $5);
            """, admin_id, action, target_anonymous_id, details, now_dt)

    async def get_recent(self, limit: int = 15, offset: int = 0) -> List[AuditLogModel]:
        """جلب أحدث الإجراءات الإدارية في سجل الرقابة مع دعم الترقيم (Pagination)"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, admin_id, action, target_anonymous_id, details, created_at
                FROM audit_logs
                ORDER BY id DESC
                LIMIT $1 OFFSET $2;
            """, limit, offset)
            return [self._record_to_audit(r) for r in rows]
