"""
Database and Concurrency Tests.
Tests atomic sequential allocation, concurrent registration safety,
persistent hourly rate limiting, and privacy wipes.
"""
import os
import asyncio
import pytest
from security.crypto import CryptoManager
from database.db_manager import DatabaseManager
from utils.key_generator import generate_encryption_key


@pytest.mark.asyncio
async def test_student_creation_and_encryption(temp_db):
    db = temp_db

    # إنشاء طالب أول بالوضع الافتراضي (معزول الهوية zero-PII)
    s1 = await db.get_or_create_student(
        telegram_id=111222333,
        full_name="طالب تجريبي أول",
        username="student_one"
    )

    assert s1.anonymous_id == 101
    # في الوضع الافتراضي للـ Repository العام، تبقى بيانات PII غير مفكوكة التشفير
    assert s1.dec_telegram_id is None
    assert s1.dec_full_name is None
    assert s1.dec_username is None

    # التحقق من أن الهوية تُفك فقط عبر IdentityVault للـ Primary Admin
    from security.identity_vault import IdentityVault
    from security.auth import admin_session_manager
    from config import Settings
    admin_settings = Settings(
        bot_token="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        channel_id=-1001234567890,
        encryption_key=db.crypto.key,
        primary_admin_id=999
    )
    admin_session_manager.create_session(999)
    identity = IdentityVault.resolve(s1, db.crypto, requesting_user_id=999, settings=admin_settings)
    assert identity.telegram_id == 111222333
    assert identity.full_name == "طالب تجريبي أول"
    assert identity.username == "student_one"

    # التحقق من أن البيانات في قاعدة البيانات مشفرة بالفعل
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow("SELECT enc_telegram_id, enc_full_name FROM students WHERE id = $1;", s1.id)
        assert "111222333" not in row["enc_telegram_id"]
        assert "طالب تجريبي" not in row["enc_full_name"]

    # إنشاء طالب ثانٍ - يجب أن يحصل على 102
    s2 = await db.get_or_create_student(
        telegram_id=444555666,
        full_name="طالب تجريبي ثان",
        username="student_two"
    )
    assert s2.anonymous_id == 102

    # نفس الطالب الأول يعود بنفس الرقم المجهول 101 دائماً
    s1_again = await db.get_or_create_student(telegram_id=111222333)
    assert s1_again.anonymous_id == 101


@pytest.mark.asyncio
async def test_concurrent_student_registrations(temp_db):
    """
    اختبار التزامن الشديد: تسجيل 30 طالباً مختلفاً في نفس اللحظة عبر asyncio.gather
    للتحقق من سلامة المخصص الذري وعدم تكرار أو تصادم أي رقم مجهول (Race-Condition Free)
    """
    db = temp_db
    num_students = 30

    async def register_student(i: int):
        return await db.get_or_create_student(
            telegram_id=1000000 + i,
            full_name=f"طالب متزامن #{i}",
            username=f"concurrent_user_{i}"
        )

    tasks = [register_student(i) for i in range(num_students)]
    results = await asyncio.gather(*tasks)

    anon_ids = [s.anonymous_id for s in results]

    # 1. التأكد من أن جميع الأرقام المجهولة فريدة بالكامل ولا يوجد أي تكرار
    assert len(anon_ids) == len(set(anon_ids)), "حدث تكرار في الأرقام المجهولة أثناء التسجيل المتزامن!"

    # 2. التأكد من أن الأرقام تمتد بشكل تسلسلي صحيح من 101 إلى 101 + num_students - 1
    assert min(anon_ids) == 101
    assert max(anon_ids) == 100 + num_students
    assert sorted(anon_ids) == list(range(101, 101 + num_students))


@pytest.mark.asyncio
async def test_post_and_reply_flow_and_author_lookup(temp_db):
    db = temp_db

    s1 = await db.get_or_create_student(111, "أحمد", "ahmed")
    s2 = await db.get_or_create_student(222, "سارة", "sara")

    # تسجيل منشور للطالب الأول برقم رسالة قناة 5001
    post = await db.record_post(
        anonymous_id=s1.anonymous_id,
        channel_message_id=5001,
        user_msg_id=10,
        media_type="text",
        content_preview="ما هو تعريف الخوارزمية؟",
        content_hash="hash_123"
    )
    assert post.channel_message_id == 5001

    # تسجيل رد من الطالب الثاني على المنشور 5001
    reply = await db.record_reply(
        parent_channel_msg_id=5001,
        reply_channel_msg_id=5002,
        anonymous_id=s2.anonymous_id,
        media_type="text",
        content_preview="الخوارزمية هي مجموعة من الخطوات المنطقية...",
        content_hash="hash_reply_456"
    )
    assert reply.reply_channel_msg_id == 5002

    # كشف هوية صاحب المنشور 5001
    found_post_author = await db.find_author_by_channel_message_id(5001)
    assert found_post_author is not None
    author_s1, context_str, _ = found_post_author
    assert author_s1.anonymous_id == 101
    assert "منشور" in context_str

    # كشف هوية صاحب الرد 5002
    found_reply_author = await db.find_author_by_channel_message_id(5002)
    assert found_reply_author is not None
    author_s2, _, _ = found_reply_author
    assert author_s2.anonymous_id == 102


@pytest.mark.asyncio
async def test_persistent_hourly_quota(temp_db):
    """اختبار الحصة الساعية المستمرة في قاعدة البيانات"""
    db = temp_db
    user_id = 99887766
    max_quota = 3

    # أول 3 مشاركات مسموحة
    ok1, c1 = await db.check_and_increment_hourly_quota(user_id, max_quota)
    assert ok1 is True
    assert c1 == 1

    ok2, c2 = await db.check_and_increment_hourly_quota(user_id, max_quota)
    assert ok2 is True
    assert c2 == 2

    ok3, c3 = await db.check_and_increment_hourly_quota(user_id, max_quota)
    assert ok3 is True
    assert c3 == 3

    # المشاركة الرابعة تُحظر
    ok4, c4 = await db.check_and_increment_hourly_quota(user_id, max_quota)
    assert ok4 is False
    assert c4 == 3


@pytest.mark.asyncio
async def test_ban_and_mute_operations(temp_db):
    db = temp_db

    s = await db.get_or_create_student(777888, "علي", "ali")
    anon_id = s.anonymous_id

    # كتم لمدة 30 دقيقة
    mute_res = await db.mute_student(anon_id, 30)
    assert mute_res is not None

    student_muted = await db.get_student_by_anonymous_id(anon_id)
    is_muted, rem_mins = db.is_student_muted(student_muted)
    assert is_muted is True
    assert 28 <= rem_mins <= 30

    # إلغاء الكتم
    await db.unmute_student(anon_id)
    student_unmuted = await db.get_student_by_anonymous_id(anon_id)
    is_muted, _ = db.is_student_muted(student_unmuted)
    assert is_muted is False

    # حظر دائم
    await db.ban_student(anon_id, "مخالفة الشروط")
    student_banned = await db.get_student_by_anonymous_id(anon_id)
    assert student_banned.is_banned is True
    assert student_banned.ban_reason == "مخالفة الشروط"


@pytest.mark.asyncio
async def test_gdpr_privacy_wipe(temp_db):
    db = temp_db

    s = await db.get_or_create_student(999, "محمد خالد", "mohamed_k")
    anon_id = s.anonymous_id

    # تطهير البيانات
    success = await db.wipe_student_data(anon_id)
    assert success is True

    # جلب الطالب بعد التطهير
    student_wiped = await db.get_student_by_anonymous_id(anon_id)
    assert student_wiped.enc_full_name == "[WIPED]"
    assert student_wiped.enc_username == "[WIPED]"
    assert student_wiped.enc_telegram_id == "[WIPED]"
    assert student_wiped.is_banned is True


@pytest.mark.asyncio
async def test_duplicate_content_posts_and_replies(temp_db):
    db = temp_db

    s = await db.get_or_create_student(12345, "طالب", "user")

    # إضافة منشور بهامش تكرار
    await db.record_post(
        anonymous_id=s.anonymous_id,
        channel_message_id=7001,
        user_msg_id=1,
        media_type="text",
        content_preview="سؤال مكرر",
        content_hash="dup_hash_777"
    )

    # فحص التكرار
    assert await db.check_duplicate_content("dup_hash_777", 300) is True
    assert await db.check_duplicate_content("non_existent_hash", 300) is False


@pytest.mark.asyncio
async def test_post_and_reply_transactions(temp_db):
    """اختبار دورة حياة معاملات المنشورات والردود (Pending -> Published / Failed)"""
    db = temp_db
    s = await db.get_or_create_student(888999, "طالب معاملات", "tx_user")

    # 1. إنشاء منشور معلق
    pending_post_id = await db.create_pending_post(
        anonymous_id=s.anonymous_id,
        user_msg_id=101,
        media_type="text",
        content_preview="سؤال معلق للتجربة"
    )
    assert pending_post_id > 0

    # 2. تأكيد نشر المنشور برقم رسالة قناة 8001
    published_post = await db.mark_post_published(pending_post_id, 8001)
    assert published_post is not None
    assert published_post.channel_message_id == 8001
    assert published_post.status == "published"

    # التحقق من تحديث عداد المنشورات
    s_updated = await db.get_student_by_anonymous_id(s.anonymous_id)
    assert s_updated.total_posts == 1

    # 3. إنشاء رد معلق ثم تعليمه كفاشل
    pending_reply_id = await db.create_pending_reply(
        parent_channel_msg_id=8001,
        anonymous_id=s.anonymous_id,
        media_type="text",
        content_preview="رد سيفشل"
    )
    assert pending_reply_id > 0
    await db.mark_reply_failed(pending_reply_id)

    # التحقق من أن عداد الردود لم يزد
    s_after_fail = await db.get_student_by_anonymous_id(s.anonymous_id)
    assert s_after_fail.total_replies == 0
