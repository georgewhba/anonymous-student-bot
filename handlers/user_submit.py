"""
User Submission Handler.
Processes new anonymous questions and media submissions, applies deep content moderation,
sanitizes media/metadata, and publishes cleanly through the mandatory PublisherService gate.
"""
from typing import Optional
from aiogram import Router, F, Bot
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.enums import ChatType
from aiogram.fsm.context import FSMContext

from database.db_manager import DatabaseManager
from config import Settings
from filters.channel_member import check_channel_membership, get_join_channel_keyboard
from moderation.publisher import publisher_service as global_publisher_service, PublisherService
from moderation.models import ModerationResult
from utils.strike_manager import SecurityShield
from utils.arabic_text import compute_content_hash
from security.escaping import build_channel_post_html
from security.media_sanitizer import media_sanitizer
from utils.logger import logger

router = Router(name="user_submit")


def create_reply_button(bot_username: str, channel_msg_id: int) -> InlineKeyboardMarkup:
    """إنشاء زر رد مجهول أسفل المنشور في القناة"""
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(
            text="💬 رد مجهول على هذا المنشور",
            url=f"https://t.me/{bot_username}?start=reply_{channel_msg_id}"
        )
    ]])


@router.message(F.chat.type == ChatType.PRIVATE)
async def handle_user_submission(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings,
    state: FSMContext,
    publisher_service: Optional[PublisherService] = None
):
    """
    معالجة إرسال الأسئلة والمشاركات والوسائط من الطالب ونشرها عبر بوابة النشر الإلزامية
    مع فحص أمني متقدم وتطهير للبيانات الوصفية وتفعيل protect_content=True
    """
    current_state = await state.get_state()
    if current_state:
        return

    if message.text and message.text.startswith("/"):
        return

    user = message.from_user
    if not user:
        return

    # 1. فحص درع مكافحة الإغراق
    if user.id not in settings.admin_ids:
        flood_ok, flood_msg = SecurityShield.check_rate_and_flood(user.id)
        if not flood_ok:
            await message.answer(flood_msg, parse_mode="HTML")
            return

    # 2. التحقق من عضوية القناة الخاصة — (bot, channel_id, user_id)
    is_member, _ = await check_channel_membership(bot, settings.channel_id, user.id)
    if not is_member and user.id not in settings.admin_ids:
        await message.answer(
            "⚠️ <b>يجب الانضمام إلى القناة الخاصة أولاً قبل إرسال الأسئلة.</b>\n"
            "انضم للقناة ثم اضغط زر التحقق:",
            parse_mode="HTML",
            reply_markup=get_join_channel_keyboard(settings.channel_invite_link)
        )
        return

    # 3. جلب أو تسجيل الطالب
    student = await db.get_or_create_student(user.id, user.full_name, user.username)

    if student.is_banned:
        await message.answer("🚫 حسابك محظور من إرسال الأسئلة.")
        return

    is_muted, rem_mins = db.is_student_muted(student)
    if is_muted:
        await message.answer(f"⏳ أنت موقوف مؤقتاً عن النشر ({rem_mins} دقيقة متبقية).")
        return

    if user.id not in settings.admin_ids:
        sub_enabled = await db.get_system_setting("submissions_enabled", "true")
        if sub_enabled != "true":
            await message.answer(
                "⏸️ <b>استقبال الأسئلة والمشاركات متوقف حالياً.</b>\n"
                "تم إيقاف النشر مؤقتاً من قِبل إدارة القناة، يرجى المحاولة لاحقاً.",
                parse_mode="HTML"
            )
            return

    # 4. استخراج النص ونوع الوسائط
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
        await message.answer("⚠️ نوع الرسالة غير مدعوم للنشر. يرجى إرسال نص أو وسائط.")
        return

    # 5-a. حد أقصى لحجم النص (4000 حرف لتجنب الرسائل التلاعبية أو محاولات إغراق قاعدة البيانات)
    MAX_TEXT_LENGTH = 4000
    if len(text_content) > MAX_TEXT_LENGTH:
        await message.answer(
            f"⚠️ <b>الرسالة طويلة جداً!</b>\n"
            f"الحد الأقصى المسموح هو <b>{MAX_TEXT_LENGTH:,}</b> حرفاً. "
            f"رسالتك تحتوي على <b>{len(text_content):,}</b> حرفاً.\n"
            f"يرجى تلخيص سؤالك قبل الإرسال.",
            parse_mode="HTML"
        )
        return

    # 5. فلتر منع تكرار الأسئلة
    content_hash = compute_content_hash(text_content, raw_file_id)
    if content_hash and user.id not in settings.admin_ids:
        is_duplicate = await db.check_duplicate_content(content_hash, within_seconds=300)
        if is_duplicate:
            await message.answer(
                "⚠️ <b>تم إرسال هذا السؤال مسبقاً مؤخراً!</b>\n"
                "يرجى تجنب تكرار إرسال نفس المحتوى لتفادي إغراق القناة.",
                parse_mode="HTML"
            )
            return

    # 5.1 فحص الحصة الساعية المستمرة (Persistent Hourly Quota)
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


    # 6. تجهيز المحتوى والوسائط المطهرة
    formatted_html = build_channel_post_html(student.anonymous_id, text_content)
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
        pending_post_id = await db.create_pending_post(
            anonymous_id=student.anonymous_id,
            user_msg_id=message.message_id,
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
            original_filename=safe_name
        )

        if not success or not sent_channel_msg:
            await db.mark_post_failed(pending_post_id)
            # تسجيل المخالفة إن وجدت عقوبات
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
                await message.answer(mod_result.reason_ar or "❌ تعذر نشر الرسالة في القناة.", parse_mode="HTML")
            return

        # تثبيت نجاح نشر المعاملة في قاعدة البيانات
        await db.mark_post_published(
            post_id=pending_post_id,
            channel_message_id=sent_channel_msg.message_id
        )

        # إضافة زر «رد مجهول» المرتبط بمعرف المنشور عبر بوابة النشر
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
            logger.warning(f"تعذر تعديل أزرار المنشور #{sent_channel_msg.message_id}: {btn_err}")

        # تأكيد النشر للطالب
        await message.answer(
            f"✅ <b>تم نشر سؤالك في القناة بنجاح!</b>\n\n"
            f"🎭 <b>نُشر باسم:</b> <code>طالب #{student.anonymous_id}</code>\n"
            f"📌 <b>رقم المنشور:</b> <code>#{sent_channel_msg.message_id}</code>\n\n"
            f"🔒 <i>هويتك وحسابك محميان بالكامل ولا يظهران لأحد.</i>",
            parse_mode="HTML"
        )

    except Exception as e:
        logger.error(f"خطأ أثناء معالجة ونشر الرسالة: {e}")
        await message.answer(
            "❌ <b>فشل النشر في القناة!</b>\n"
            "يرجى التأكد من صلاحيات البوت في القناة والمحاولة لاحقاً.",
            parse_mode="HTML"
        )
    finally:
        if clean_media_path:
            media_sanitizer.cleanup_file(clean_media_path)
