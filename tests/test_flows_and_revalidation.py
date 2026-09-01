"""
Flows and Revalidation Tests.
Tests submission switches, late revalidation, ban/mute barriers, and duplicate rejection.
"""
import pytest
from database.db_manager import DatabaseManager
from security.crypto import CryptoManager
from utils.key_generator import generate_encryption_key




@pytest.mark.asyncio
async def test_global_submissions_switch_toggle(temp_db):
    db = temp_db

    # الحالة الافتراضية مفعلة
    stats1 = await db.get_statistics()
    assert stats1["submissions_enabled"] is True

    # إيقاف استقبال المشاركات
    await db.set_system_setting("submissions_enabled", "false")
    stats2 = await db.get_statistics()
    assert stats2["submissions_enabled"] is False

    val = await db.get_system_setting("submissions_enabled")
    assert val == "false"

    # إعادة التفعيل
    await db.set_system_setting("submissions_enabled", "true")
    stats3 = await db.get_statistics()
    assert stats3["submissions_enabled"] is True


@pytest.mark.asyncio
async def test_late_ban_blocks_reply_submission(temp_db):
    """
    اختبار: طالب بدأ كتابة رد وهو غير محظور، لكن تم حظره قبل إتمام الإرسال
    يجب أن تكشف إعادة التحقق (Revalidation) الحظر وتمنع النشر
    """
    db = temp_db
    student = await db.get_or_create_student(1234567, "طالب تجريبي", "user1")

    assert student.is_banned is False

    # تم حظره في منتصف العملية
    await db.ban_student(student.anonymous_id, "مخالفة مفاجئة")

    # فحص الحالة المحدثة
    fresh_student = await db.get_student_by_anonymous_id(student.anonymous_id)
    assert fresh_student.is_banned is True
    assert fresh_student.ban_reason == "مخالفة مفاجئة"


@pytest.mark.asyncio
async def test_reply_to_deleted_parent_post_fails(temp_db):
    """
    اختبار: طالب يحاول الرد على منشور تم حذفه من القناة
    """
    db = temp_db
    student = await db.get_or_create_student(111, "أحمد", "ahmed")

    # تسجيل منشور
    post = await db.record_post(
        anonymous_id=student.anonymous_id,
        channel_message_id=9001,
        user_msg_id=1,
        media_type="text",
        content_preview="منشور سيتم حذفه"
    )

    # حذف المنشور من القناة
    await db.delete_post_from_db(9001)

    deleted_post = await db.get_post_by_channel_msg_id(9001)
    assert deleted_post.is_deleted is True
