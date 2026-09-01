"""
Admin Messaging Handler.
Enforces Primary Admin authorization for private direct messaging to anonymous students.
Guarantees zero leakage of moderator/admin personal accounts or student Telegram IDs.
"""
from aiogram import Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton

from database.db_manager import DatabaseManager
from config import Settings
from filters.admin_filter import IsAdmin
from security.auth import admin_session_manager, is_admin_session_valid
from security.escaping import escape_user_content
from utils.logger import logger, send_admin_log_notification

router = Router(name="admin_messaging")
router.message.filter(IsAdmin())


@router.message(Command("dm"))
async def handle_admin_dm_command(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings
):
    """
    إرسال رسالة خاصة من المسؤول الأساسي إلى طالب محدد عبر البوت
    دون أن يعرف الطالب حساب المسؤول، ودون كشف حساب الطالب للآخرين
    الاستخدام: /dm <رقم_الطالب> <نص الرسالة> (Primary Admin فقط)
    """
    user_id = message.from_user.id if message.from_user else 0

    if not is_admin_session_valid(user_id, settings):
        await message.answer(
            "🔒 <b>لوحة التحكم مقفلة!</b>\nيرجى إرسال أمر <code>/admin</code> وإدخال كلمة المرور أولاً لتفعيل الجلسة.",
            parse_mode="HTML"
        )
        return

    # Server-Side RBAC Check: Primary Admin only
    if not admin_session_manager.is_primary_admin(user_id, settings):
        await message.answer(
            "⛔ <b>غير مصرح:</b> المراسلة الخاصة للطلاب متاحة حصرياً للمسؤول الأساسي (Primary Admin).",
            parse_mode="HTML"
        )
        return

    parts = message.text.split(maxsplit=2) if message.text else []
    if len(parts) < 3 or not parts[1].lstrip("#").isdigit():
        await message.answer(
            "⚠️ <b>طريقة الاستخدام:</b>\n"
            "<code>/dm 154 نص الرسالة أو التنبيه الخاص بالطالب</code>",
            parse_mode="HTML"
        )
        return

    anon_id = int(parts[1].lstrip("#"))
    dm_text = parts[2]

    student = await db.get_student_by_anonymous_id(anon_id)
    if not student:
        await message.answer(f"❌ لم يتم العثور على طالب بالرقم <b>#{anon_id}</b>.", parse_mode="HTML")
        return

    safe_dm_text = escape_user_content(dm_text)

    # صياغة الرسالة الرسمية للطالب
    student_msg = (
        f"📩 <b>رسالة رسمية من إدارة القناة</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n\n"
        f"{safe_dm_text}\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔒 <i>هذه الرسالة خاصة بك وموجهة من إدارة القناة التعليمية.</i>"
    )

    # إعداد زر الرد على المشرف
    # نمرر user_id (وهو id المشرف) في الكول باك داتا
    reply_markup = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="↩️ رد على المشرف", callback_data=f"dm_reply_{user_id}")]
        ]
    )

    try:
        from security.identity_vault import IdentityVault
        delivered = await IdentityVault.send_direct_message(
            bot=bot,
            student=student,
            crypto=db.crypto,
            requesting_user_id=user_id,
            settings=settings,
            text=student_msg,
            parse_mode="HTML",
            reply_markup=reply_markup
        )
        if not delivered:
            await message.answer(
                f"❌ <b>تعذر تسليم الرسالة إلى طالب #{anon_id}.</b>\n"
                f"قد يكون الطالب قام بحظر البوت أو أن حسابه تم تطهيره.",
                parse_mode="HTML"
            )
            return

        # تسجيل الإجراء في السجل بدون تسريب بيانات PII
        await db.log_audit_action(
            admin_id=user_id,
            action="DM_STUDENT",
            target_anonymous_id=anon_id,
            details=f"إرسال رسالة خاصة لطالب #{anon_id}"
        )

        await send_admin_log_notification(
            bot,
            settings.admin_log_channel_id,
            f"✉️ <b>رسالة خاصة إلى طالب</b>\n"
            f"إلى: <code>طالب #{anon_id}</code>"
        )

        await message.answer(
            f"✅ <b>تم إرسال الرسالة الخاصة إلى طالب #{anon_id} بنجاح!</b>\n\n"
            f"📝 <b>نص الرسالة:</b>\n<i>\"{safe_dm_text}\"</i>",
            parse_mode="HTML"
        )

    except Exception as e:
        logger.error(f"فشل إرسال الرسالة الخاصة: {e}")
        await message.answer(
            f"❌ <b>تعذر تسليم الرسالة إلى طالب #{anon_id}.</b>\n"
            f"قد يكون الطالب قام بحظر البوت أو حذف حسابه.",
            parse_mode="HTML"
        )
