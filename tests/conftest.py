"""
Pytest Central Configuration and Database Fixtures for PostgreSQL Testing.
"""
import os
import pytest
import asyncio
from security.crypto import CryptoManager
from database.db_manager import DatabaseManager
from utils.key_generator import generate_encryption_key

TEST_DB_URL = os.environ.get(
    "TEST_DATABASE_URL",
    os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@127.0.0.1:5433/anonymous_bot_test")
)


@pytest.fixture(scope="session")
def test_db_url() -> str:
    return TEST_DB_URL


@pytest.fixture
def test_crypto() -> CryptoManager:
    key = generate_encryption_key()
    return CryptoManager(key)


@pytest.fixture
def master_crypto() -> CryptoManager:
    key = generate_encryption_key()
    return CryptoManager(key)


async def _get_clean_test_db(crypto: CryptoManager) -> DatabaseManager:
    """تهيئة قاعدة بيانات اختبارية نظيفة مع تفريغ الجداول وضبط العدادات"""
    db = DatabaseManager(
        db_url=TEST_DB_URL,
        crypto=crypto,
        pool_min=2,
        pool_max=10
    )
    await db.init_db()

    async with db.pool.acquire() as conn:
        await conn.execute("""
            TRUNCATE TABLE replies, posts, audit_logs, submission_quotas,
            security_events, admin_login_attempts, admin_sessions,
            admin_credentials, banned_fingerprints, students, system_settings CASCADE;
            ALTER SEQUENCE anonymous_student_id_seq RESTART WITH 101;
        """)
        await conn.execute("""
            INSERT INTO system_settings (key, value, updated_at)
            VALUES ('submissions_enabled', 'true', NOW())
            ON CONFLICT (key) DO UPDATE SET value = 'true';
        """)

    return db


@pytest.fixture
async def temp_db(test_crypto):
    db = await _get_clean_test_db(test_crypto)
    yield db
    await db.close()


@pytest.fixture
async def vault_db(test_crypto):
    db = await _get_clean_test_db(test_crypto)
    yield db
    await db.close()


@pytest.fixture
async def test_db(test_crypto):
    db = await _get_clean_test_db(test_crypto)
    yield db
    await db.close()


@pytest.fixture
async def acceptance_db(master_crypto):
    db = await _get_clean_test_db(master_crypto)
    yield db
    await db.close()
