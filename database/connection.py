"""
PostgreSQL Central Connection Pool and Lifecycle Manager.
Provides production-grade connection pooling with asyncpg, transaction management,
safe health checks, bounded timeouts, and SSL support.
"""
import ssl
import time
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager
import asyncpg
from asyncpg.pool import Pool
from asyncpg.connection import Connection

from utils.logger import logger


class DatabasePool:
    """
    مدير مجمع اتصالات PostgreSQL المركزي (Central asyncpg Pool Manager)
    يدير دورة حياة الاتصالات، المعاملات، وفحص الجاهزية دون تسريب بيانات الاعتماد.
    """

    def __init__(
        self,
        dsn: str,
        min_size: int = 5,
        max_size: int = 20,
        command_timeout: float = 10.0,
        connect_timeout: float = 10.0,
        ssl_mode: Optional[str] = None
    ):
        self.dsn = dsn
        self.min_size = min_size
        self.max_size = max_size
        self.command_timeout = command_timeout
        self.connect_timeout = connect_timeout
        self.ssl_mode = ssl_mode
        self._pool: Optional[Pool] = None

    def _get_ssl_context(self, effective_ssl_mode: Optional[str]) -> Optional[ssl.SSLContext]:
        """إنشاء سياق SSL/TLS إذا تم تمكينه في الإعدادات أو رابط DSN"""
        if not effective_ssl_mode or effective_ssl_mode.lower() in ("disable", "none", "off", "false"):
            return None

        ctx = ssl.create_default_context()
        if effective_ssl_mode.lower() in ("require", "allow", "prefer"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif effective_ssl_mode.lower() in ("verify-ca", "verify-full"):
            ctx.check_hostname = (effective_ssl_mode.lower() == "verify-full")
            ctx.verify_mode = ssl.CERT_REQUIRED

        return ctx

    async def initialize(self) -> None:
        """تهيئة وفتح مجمع الاتصالات والتحقق من سلامته"""
        if self._pool is not None:
            return

        # تحليل وتطهير رابط DSN لاستخراج وتوافق معايير SSL مع كافة مزودي السحاب المجاني (Neon / Supabase / Render)
        dsn_clean = self.dsn
        effective_ssl_mode = self.ssl_mode

        if "?" in self.dsn:
            import urllib.parse
            parsed = urllib.parse.urlparse(self.dsn)
            query_params = urllib.parse.parse_qs(parsed.query)
            if "sslmode" in query_params:
                effective_ssl_mode = query_params["sslmode"][0]
            # إزالة استعلامات sslmode غير المدعومة كبارامتر مباشر في asyncpg dsn
            clean_query = urllib.parse.urlencode({k: v for k, v in query_params.items() if k.lower() != "sslmode"}, doseq=True)
            dsn_clean = urllib.parse.urlunparse(parsed._replace(query=clean_query))

        ssl_ctx = self._get_ssl_context(effective_ssl_mode)
        logger.info(
            f"🐘 جاري إنشاء مجمع اتصالات PostgreSQL (Min: {self.min_size}, Max: {self.max_size}, Timeout: {self.command_timeout}s)..."
        )
        try:
            self._pool = await asyncpg.create_pool(
                dsn=dsn_clean,
                min_size=self.min_size,
                max_size=self.max_size,
                command_timeout=self.command_timeout,
                timeout=self.connect_timeout,
                ssl=ssl_ctx
            )
            # إجراء فحص أولي للاتصال
            latency = await self.ping()
            logger.info(f"✅ تم الاتصال بقاعدة بيانات PostgreSQL بنجاح (زمن الاستجابة: {latency:.2f}ms)")
        except Exception as e:
            logger.error(f"❌ فشل فتح مجمع اتصالات PostgreSQL: {e}")
            raise

    async def close(self) -> None:
        """إغلاق مجمع الاتصالات بشكل آمن (Graceful Shutdown)"""
        if self._pool is not None:
            logger.info("جاري إغلاق مجمع اتصالات PostgreSQL بأمان...")
            await self._pool.close()
            self._pool = None

    @property
    def raw_pool(self) -> Pool:
        """الحصول على المجمع الخام"""
        if self._pool is None:
            raise RuntimeError("مجمع اتصالات قاعدة البيانات غير مهيأ بعد. يرجى استدعاء initialize() أولاً.")
        return self._pool

    @asynccontextmanager
    async def acquire(self):
        """الحصول على اتصال من المجمع مع الإرجاع التلقائي"""
        pool = self.raw_pool
        conn: Connection = await pool.acquire()
        try:
            yield conn
        finally:
            await pool.release(conn)

    @asynccontextmanager
    async def transaction(self):
        """إدارة معاملة ذرية متكاملة (Transaction Context) مع تراجع تلقائي عند الأخطاء"""
        pool = self.raw_pool
        conn: Connection = await pool.acquire()
        tx = conn.transaction()
        await tx.start()
        try:
            yield conn
            await tx.commit()
        except Exception:
            await tx.rollback()
            raise
        finally:
            await pool.release(conn)

    async def ping(self) -> float:
        """
        فحص صحة واستجابة قاعدة البيانات (Health Check).
        يرجع زمن الاستجابة بالميلي ثانية (ms).
        """
        start = time.perf_counter()
        async with self.acquire() as conn:
            val = await conn.fetchval("SELECT 1;")
            if val != 1:
                raise RuntimeError("PostgreSQL healthcheck returned unexpected value")
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return elapsed_ms

    def get_pool_stats(self) -> Dict[str, Any]:
        """إحصائيات استهلاك مجمع الاتصالات (Observability)"""
        if self._pool is None:
            return {"status": "uninitialized"}
        return {
            "status": "active",
            "size": self._pool.get_size(),
            "min_size": self._pool.get_min_size(),
            "max_size": self._pool.get_max_size(),
            "idle": self._pool.get_idle_size(),
        }
