"""
Handler for students replying to Direct Messages sent by an admin.
Maintains student anonymity while allowing two-way communication.
"""
from aiogram import Router, F, Bot
from aiogram.types import Message, CallbackQuery
from aiogram.fsm.context import FSMContext

from database.db_manager import DatabaseManager
from config import Settings
from states.submission import SubmissionState
from security.escaping import escape_user_content
from utils.logger import logger

router = Router(name="student_dm_reply")

@router.callback_query(F.data.startswith("dm_reply_"))
async def process_dm_reply_callback(
    callback: CallbackQuery,
    state: FSMContext,
    db: DatabaseManager
):
    """التقاط ضغطة الطالب على زر الرد على المشرف"""
    user_id = callback.from_user.id
    
    # فحص تسجيل الطالب
    student = await db.get_student_by_telegram_id(user_id)
    if not student or student.is_banned:
        await callback.answer("حسابك غير مسجل أو محظور.", show_alert=True)
        return

    admin_id_str = callback.data.replace("dm_reply_", "")
    if not admin_id_str.isdigit():
        await callback.answer("بيانات المشرف غير صالحة.", show_alert=True)
        return

    admin_id = int(admin_id_str)

    # حفظ حالة الرد وتخزين رقم المشرف المستهدف
    await state.set_state(SubmissionState.waiting_for_dm_reply)
    await state.update_data(target_admin_id=admin_id)

    await callback.message.answer(
        "✍️ <b>اكتب ردك الآن:</b>\n\n"
        "<i>سيتم إرسال ردك في رسالة خاصة للمشرف مع إخفاء هويتك تماماً.</i>",
        parse_mode="HTML"
    )
    await callback.answer()


@router.message(SubmissionState.waiting_for_dm_reply)
async def process_dm_reply_content(
    message: Message,
    state: FSMContext,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings
):
    """استلام نص الرد وتمريره للمشرف"""
    user_id = message.from_user.id if message.from_user else 0
    student = await db.get_student_by_telegram_id(user_id)

    if not student or student.is_banned:
        await message.answer("⚠️ حسابك غير مصرح له بالإرسال.")
        await state.clear()
        return

    # نقبل فقط الردود النصية حالياً
    if not message.text:
        await message.answer("⚠️ يرجى إرسال نص فقط للرد على المشرف.")
        return

    data = await state.get_data()
    target_admin_id = data.get("target_admin_id")

    if not target_admin_id:
        await message.answer("⚠️ حدث خطأ في استرجاع بيانات المشرف. يرجى المحاولة مرة أخرى.")
        await state.clear()
        return

    safe_text = escape_user_content(message.text)
    anon_id = student.anonymous_id

    admin_msg = (
        f"💬 <b>رد خاص من الطالب #{anon_id}</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n\n"
        f"{safe_text}\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"<i>يمكنك الرد عليه باستخدام:</i>\n"
        f"<code>/dm {anon_id} الرسالة...</code>"
    )

    try:
        await bot.send_message(
            chat_id=target_admin_id,
            text=admin_msg,
            parse_mode="HTML"
        )
        await message.answer("✅ <b>تم إرسال ردك للمشرف بنجاح!</b>", parse_mode="HTML")
    except Exception as e:
        logger.error(f"فشل إرسال رد الطالب #{anon_id} للمشرف {target_admin_id}: {e}")
        await message.answer("❌ عذراً، تعذر إرسال الرد للمشرف حالياً.")

    # مسح الحالة بعد الإرسال
    await state.clear()
