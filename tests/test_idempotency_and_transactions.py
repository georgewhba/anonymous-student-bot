"""
Idempotency and Message Transaction Test Suite.
Verifies atomic sequence generation, crash-resilience with pending status,
and concurrent request handling.
"""
import asyncio
import pytest
from database.db_manager import DatabaseManager
from security.crypto import CryptoManager
from utils.key_generator import generate_encryption_key


@pytest.mark.asyncio
async def test_atomic_sequence_monotonic_increment(temp_db):
    """التحقق من أن الأرقام المجهولة تتزايد برتابة ودون فجوات غير متوقعة أو تصادم"""
    db = temp_db
    students = []
    for i in range(15):
        s = await db.get_or_create_student(
            telegram_id=200000 + i,
            full_name=f"طالب رقم {i}",
            username=f"student_{i}"
        )
        students.append(s)

    anon_ids = [s.anonymous_id for s in students]
    assert anon_ids == list(range(101, 101 + 15))


@pytest.mark.asyncio
async def test_high_concurrency_race_condition_immunity(temp_db):
    """التحقق من مناعة النظام الكاملة ضد الـ Race Conditions عند تسجيل 50 طالباً متزامناً"""
    db = temp_db
    total = 50

    async def register(idx):
        return await db.get_or_create_student(
            telegram_id=900000 + idx,
            full_name=f"متزامن {idx}",
            username=f"user_{idx}"
        )

    tasks = [register(i) for i in range(total)]
    results = await asyncio.gather(*tasks)

    anon_ids = [s.anonymous_id for s in results]
    assert len(anon_ids) == len(set(anon_ids))
    assert min(anon_ids) == 101
    assert max(anon_ids) == 100 + total


@pytest.mark.asyncio
async def test_message_transaction_failure_recovery(temp_db):
    """التحقق من سلوك المعاملات عند فشل النشر في القناة"""
    db = temp_db
    s = await db.get_or_create_student(555666, "طالب تجربة الفشل", "fail_user")

    # 1. إنشاء معاملة معلقة
    pending_id = await db.create_pending_post(
        anonymous_id=s.anonymous_id,
        user_msg_id=77,
        media_type="text",
        content_preview="رسالة لم تكتمل"
    )

    # 2. تسجيل الفشل
    await db.mark_post_failed(pending_id)

    # التحقق من أن عدد المنشورات الناجحة للطالب بقي 0
    s_check = await db.get_student_by_anonymous_id(s.anonymous_id)
    assert s_check.total_posts == 0
