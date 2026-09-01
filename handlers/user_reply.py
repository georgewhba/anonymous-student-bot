"""
Anonymous Reply Handler.
Enforces multi-stage revalidation at the exact moment of final submission,
and publishes strictly through the mandatory PublisherService gate.
"""
from typing import Optional
from aiogram import Router, F, Bot
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.fsm.context import FSMContext

from database.db_manager import DatabaseManager
from database.models import StudentModel
from config import Settings
from filters.channel_member import check_channel_membership, get_join_channel_keyboard
from moderation.publisher import publisher_service as global_publisher_service, PublisherService
from utils.strike_manager import SecurityShield
from utils.arabic_text import compute_content_hash
from security.escaping import build_channel_reply_html
from security.media_sanitizer import media_sanitizer
from states.submission import SubmissionState
from utils.logger import logger

router = Router(name="user_reply")

# SubmissionState هو مصدر الحقيقة الوحيد للـ FSM — مشترك مع user_start deep-link
# الاسم المحلي للتوافق مع بقية الكود في هذا الملف
ReplyState = SubmissionState


def get_cancel_reply_keyboard() -> InlineKeyboardMarkup:
    """زر إلغاء كتابة الرد"""
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="❌ إلغاء الرد", callback_data="cancel_reply")
    ]])


def create_reply_button(bot_username: str, channel_msg_id: int) -> InlineKeyboardMarkup:
    """إنشاء زر رد مجهول أسفل الرد في القناة"""
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(
            text="💬 رد مجهول على هذا المنشور",
            url=f"https://t.me/{bot_username}?start=reply_{channel_msg_id}"
        )
    ]])


async def initiate_reply_flow(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings,
    state: FSMContext,
    target_channel_msg_id: int,
    student: StudentModel
):
    """بدء عملية الرد المجهول عند الضغط على زر الرد في القناة"""
    is_member, _ = await check_channel_membership(bot, settings.channel_id, message.from_user.id)  # noqa: (bot, channel_id, user_id)
    if not is_member and message.from_user.id not in settings.admin_ids:
        await message.answer(
            "⚠️ <b>يجب الانضمام إلى القناة الخاصة أولاً لتتمكن من كتابة الردود.</b>",
            parse_mode="HTML",
            reply_markup=get_join_channel_keyboard(settings.channel_invite_link)
        )
        return

    if student.is_banned:
        await message.answer("🚫 حسابك محظور من المشاركة.")
        return

    is_muted, rem_mins = db.is_student_muted(student)
    if is_muted:
        await message.answer(f"⏳ أنت موقوف مؤقتاً عن المشاركة ({rem_mins} دقيقة متبقية).")
        return

    if message.from_user.id not in settings.admin_ids:
        sub_enabled = await db.get_system_setting("submissions_enabled", "true")
        if sub_enabled != "true":
            await message.answer(
                "⏸️ <b>استقبال المشاركات والردود متوقف حالياً.</b>\n"
                "تم إيقاف النشر مؤقتاً من قِبل إدارة القناة، يرجى المحاولة لاحقاً.",
                parse_mode="HTML"
            )
            return

    post = await db.get_post_by_channel_msg_id(target_channel_msg_id)
    reply = await db.get_reply_by_channel_msg_id(target_channel_msg_id) if not post else None

    if not post and not reply:
        await message.answer(f"⚠️ المنشور <b>#{target_channel_msg_id}</b> غير موجود أو تم حذفه مسبقاً.", parse_mode="HTML")
        return

    snippet = ""
    if post:
        snippet = f"\n\n📝 <b>مقتطف من المنشور:</b>\n<i>\"{post.content_preview[:120]}\"</i>"
    elif reply:
        snippet = f"\n\n📝 <b>مقتطف من الرد الأصلي:</b>\n<i>\"{reply.content_preview[:120]}\"</i>"

    await state.set_state(SubmissionState.waiting_for_reply)
    await state.update_data(parent_channel_msg_id=target_channel_msg_id)

    prompt_text = (
        f"🔄 <b>كتابة رد مجهول</b>\n"
        f"أنت تقوم بالرد على منشور <b>#{target_channel_msg_id}</b> داخل القناة.{snippet}\n\n"
        f"✍️ <b>أرسل الآن ردك (نص، صورة، صوت، أو ملف):</b>\n"
        f"سيتم النشر باسمك المجهول: <code>طالب #{student.anonymous_id}</code>\n"
        f"🔒 <i>لن تظهر هويتك الحقيقية أبداً.</i>"
    )

    await message.answer(
        prompt_text,
        parse_mode="HTML",
        reply_markup=get_cancel_reply_keyboard()
    )


@router.callback_query(F.data == "cancel_reply")
async def callback_cancel_reply(callback: CallbackQuery, state: FSMContext):
    """إلغاء عملية كتابة الرد"""
    await state.clear()
    await callback.message.edit_text("❌ <b>تم إلغاء كتابة الرد.</b>", parse_mode="HTML")
    await callback.answer("تم الإلغاء")


@router.message(SubmissionState.waiting_for_reply)
async def handle_reply_content_submission(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings,
    state: FSMContext,
    publisher_service: Optional[PublisherService] = None
):
    """
    معالجة استلام الرد ونشره في القناة كتعقيب مجهول عبر Publisher Gate
    مع إعادة التحقق الصارم لحظة النشر
    """
    user = message.from_user
    if not user:
        return

    if message.text and message.text.strip() == "/cancel":
        await state.clear()
        await message.answer("❌ تم إلغاء كتابة الرد.")
        return

    data = await state.get_data()
    parent_channel_msg_id = data.get("parent_channel_msg_id")

    if not parent_channel_msg_id:
        await state.clear()
        await message.answer("⚠️ حدث خطأ في تحديد المنشور الأصلي. يرجى إعادة المحاولة من زر الرد.")
        return

    # =========================================================================
    # 🚨 CRITICAL: إعادة التحقق الكامل لحظة النشر الفعلي (Late Revalidation)
    # =========================================================================

    is_member, _ = await check_channel_membership(bot, settings.channel_id, user.id)  # (bot, channel_id, user_id)
    if not is_member and user.id not in settings.admin_ids:
        await state.clear()
        await message.answer(
            "⚠️ <b>تم إلغاء نشر الرد:</b> يجب أن تكون عضواً نشطاً في القناة الخاصة.",
            parse_mode="HTML",
            reply_markup=get_join_channel_keyboard(settings.channel_invite_link)
        )
        return

    student = await db.get_or_create_student(user.id, user.full_name, user.username)

    if student.is_banned:
        await state.clear()
        await message.answer("🚫 حسابك محظور من المشاركة.")
        return

    is_muted, rem_mins = db.is_student_muted(student)
    if is_muted:
        await state.clear()
        await message.answer(f"⏳ أنت موقوف مؤقتاً عن المشاركة ({rem_mins} دقيقة متبقية).")
        return

    if user.id not in settings.admin_ids:
        sub_enabled = await db.get_system_setting("submissions_enabled", "true")
        if sub_enabled != "true":
            await state.clear()
            await message.answer(
                "⏸️ <b>استقبال المشاركات والردود متوقف حالياً.</b>\n"
                "تم إيقاف النشر مؤقتاً من قِبل إدارة القناة.",
                parse_mode="HTML"
            )
            return

    text_content = message.text or message.caption or ""
    media_type = "text"
    raw_file_id: Optional[str] = None
    original_filename: Optional[str] = None

    if message.photo:
        media_type = "photo"
        raw_file_id = message.photo[-1].file_id
    elif message.animation:
        media_type = "animation"
        raw_file_id = message.animation.file_id
    elif message.audio:
        media_type = "audio"
        raw_file_id = message.audio.file_id
    elif message.voice:
        media_type = "voice"
        raw_file_id = message.voice.file_id
    elif message.video_note:
        media_type = "video_note"
        raw_file_id = message.video_note.file_id
    elif message.sticker:
        media_type = "sticker"
        raw_file_id = message.sticker.file_id
    elif message.document:
        media_type = "document"
        raw_file_id = message.document.file_id
        original_filename = message.document.file_name
    elif message.video:
        media_type = "video"
        raw_file_id = message.video.file_id
    elif not text_content:
        await message.answer("⚠️ يرجى إرسال نص أو وسائط للرد.")
        return

    # حد أقصى لحجم النص
    MAX_TEXT_LENGTH = 4000
    if len(text_content) > MAX_TEXT_LENGTH:
        await message.answer(
            f"⚠️ <b>الرسالة طويلة جداً!</b>\n"
            f"الحد الأقصى المسموح هو <b>{MAX_TEXT_LENGTH:,}</b> حرفاً. "
            f"رسالتك تحتوي على <b>{len(text_content):,}</b> حرفاً.\n"
            f"يرجى تلخيص ردك قبل الإرسال.",
            parse_mode="HTML"
        )
        return

    # فحص تكرار المحتوى في الردود
    content_hash = compute_content_hash(text_content, raw_file_id)
    if content_hash and user.id not in settings.admin_ids:
        is_duplicate = await db.check_duplicate_content(content_hash, within_seconds=300)
        if is_duplicate:
            await message.answer(
                "⚠️ <b>تم إرسال هذا الرد مسبقاً مؤخراً!</b>\n"
                "يرجى تجنب تكرار إرسال نفس المحتوى.",
                parse_mode="HTML"
            )
            return

    # فحص الحصة الساعية المستمرة (Persistent Hourly Quota)
    if user.id not in settings.admin_ids:
        is_allowed, cur_count = await db.check_and_increment_hourly_quota(
            telegram_id=user.id,
            max_submissions_per_hour=settings.max_submissions_per_hour
        )
        if not is_allowed:
            await message.answer(
                f"⚠️ <b>تجاوزت الحد الأقصى للمشاركات خلال هذه الساعة!</b>\n"
                f"الحد المسموح به هو <b>{settings.max_submissions_per_hour}</b> مشاركة/ساعة.\n"
                f"يرجى الانتظار حتى بداية الساعة القادمة.",
                parse_mode="HTML"
            )
            return

    formatted_html = build_channel_reply_html(student.anonymous_id, parent_channel_msg_id, text_content)
    preview_summary = text_content[:150] if text_content else f"[{media_type}]"

    clean_media_path: Optional[str] = None
    safe_name: Optional[str] = original_filename

    try:
        if raw_file_id:
            clean_media_path, safe_name = await media_sanitizer.download_and_sanitize(
                bot=bot,
                file_id=raw_file_id,
                media_type=media_type,
                original_filename=original_filename
            )

        # -------------------------------------------------------------
        # 🚨 النشر الحصري عبر بوابة النشر الإلزامية (Publisher Gate) مع تسجيل المعاملة
        # -------------------------------------------------------------
        pending_reply_id = await db.create_pending_reply(
            parent_channel_msg_id=parent_channel_msg_id,
            anonymous_id=student.anonymous_id,
            media_type=media_type,
            content_preview=preview_summary,
            media_file_id=raw_file_id,
            content_hash=content_hash,
            original_filename=original_filename
        )

        active_publisher = publisher_service or global_publisher_service
        success, sent_channel_msg, mod_result = await active_publisher.publish_post(
            bot=bot,
            channel_id=settings.channel_id,
            media_type=media_type,
            formatted_html=formatted_html,
            raw_text=text_content,
            media_path=clean_media_path,
            original_filename=safe_name,
            reply_to_message_id=parent_channel_msg_id
        )

        if not success or not sent_channel_msg:
            await db.mark_reply_failed(pending_reply_id)
            if not mod_result.is_allowed and user.id not in settings.admin_ids:
                strike_num, penalty_msg = await SecurityShield.record_violation(
                    user_id=user.id,
                    anonymous_id=student.anonymous_id,
                    violation_name=mod_result.category.value,
                    db=db,
                    bot=bot,
                    admin_log_channel_id=settings.admin_log_channel_id
                )
                full_reply = f"{mod_result.reason_ar}"
                if penalty_msg:
                    full_reply += f"\n\n{penalty_msg}"
                await message.answer(full_reply, parse_mode="HTML")
            else:
                await message.answer(mod_result.reason_ar or "❌ تعذر نشر الرد في القناة.", parse_mode="HTML")
            return

        # تثبيت نجاح نشر المعاملة في قاعدة البيانات
        await db.mark_reply_published(
            reply_id=pending_reply_id,
            reply_channel_msg_id=sent_channel_msg.message_id
        )

        try:
            bot_info = await bot.get_me()
            reply_markup = create_reply_button(bot_info.username, sent_channel_msg.message_id)
            # استخدام active_publisher (لا publisher_service) لأنه قد يكون None من DI
            await active_publisher.edit_channel_message_reply_markup(
                bot=bot,
                channel_id=settings.channel_id,
                message_id=sent_channel_msg.message_id,
                reply_markup=reply_markup
            )
        except Exception as btn_err:
            logger.warning(f"تعذر تعديل أزرار الرد #{sent_channel_msg.message_id}: {btn_err}")

        await state.clear()

        await message.answer(
            f"✅ <b>تم نشر ردك بنجاح داخل القناة!</b>\n\n"
            f"🎭 <b>نُشر باسم:</b> <code>طالب #{student.anonymous_id}</code>\n"
            f"📌 <b>رقم الرد:</b> <code>#{sent_channel_msg.message_id}</code>\n"
            f"🔗 <b>تعقيباً على:</b> <code>#{parent_channel_msg_id}</code>\n\n"
            f"🔒 <i>هويتك وحسابك محميان بالكامل.</i>",
            parse_mode="HTML"
        )

    except Exception as e:
        logger.error(f"خطأ أثناء نشر الرد في القناة: {e}")
        await message.answer(
            "❌ <b>حدث خطأ أثناء نشر الرد.</b>\n"
            "تأكد من وجود الرسالة الأصلية وصلاحيات البوت في القناة.",
            parse_mode="HTML"
        )
    finally:
        if clean_media_path:
            media_sanitizer.cleanup_file(clean_media_path)
