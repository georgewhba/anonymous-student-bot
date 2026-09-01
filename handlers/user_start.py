"""
User Start and Onboarding Handler.
Handles /start, deep-links, /my_id, /rules, /help, and /forget_me (Privacy Wipe).
"""
from aiogram import Router, F, Bot
from aiogram.filters import CommandStart, Command
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.fsm.context import FSMContext

from database.db_manager import DatabaseManager
from config import Settings
from filters.channel_member import check_channel_membership, get_join_channel_keyboard
from utils.logger import logger

router = Router(name="user_start")


@router.message(CommandStart())
async def handle_start_command(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings,
    state: FSMContext
):
    """معالجة أمر /start والتسجيل المجهول أو التوجيه للرد السريع"""
    user = message.from_user
    if not user:
        return

    await state.clear()

    # تسجيل الطالب أو جلب بياناته المشفرة
    student = await db.get_or_create_student(
        telegram_id=user.id,
        full_name=user.full_name,
        username=user.username
    )

    # فحص الروابط العميقة (Deep Links) مثل: /start reply_123
    text = message.text or ""
    parts = text.split()
    if len(parts) > 1 and parts[1].startswith("reply_"):
        try:
            target_post_id = int(parts[1].replace("reply_", ""))
            # حفظ الهدف في حالة المستخدم
            from states.submission import SubmissionState
            await state.set_state(SubmissionState.waiting_for_reply)
            await state.update_data(parent_channel_msg_id=target_post_id)

            await message.answer(
                f"💬 <b>أنت الآن تقوم بالرد بشكل مجهول على المنشور رقم #{target_post_id}</b>\n\n"
                f"اكتب ردك أو أرسل وسائطك (صورة/ملف/صوت) وسيتم نشره مجهولاً برقمك المجهول: <code>طالب #{student.anonymous_id}</code>\n\n"
                f"<i>(للإلغاء أرسل /cancel في أي وقت)</i>",
                parse_mode="HTML"
            )
            return
        except ValueError:
            pass

    # فحص العضوية الإلزامية في القناة — (bot, channel_id, user_id)
    is_member, _ = await check_channel_membership(bot, settings.channel_id, user.id)
    if not is_member and settings.channel_invite_link:
        join_kb = get_join_channel_keyboard(settings.channel_invite_link)
        await message.answer(
            f"👋 <b>أهلاً بك يا طالب #{student.anonymous_id}!</b>\n\n"
            f"للبدء في إرسال الأسئلة والمشاركات المجهولة، يرجى الانضمام أولاً إلى القناة الرسمية:",
            reply_markup=join_kb,
            parse_mode="HTML"
        )
        return

    welcome_text = (
        f"👋 <b>أهلاً بك في بوت الأسئلة والمشاركات الطلابية المجهولة!</b>\n\n"
        f"🎭 <b>رقمك المجهول الثابت:</b> <code>طالب #{student.anonymous_id}</code>\n\n"
        f"🔒 <b>خصوصيتك محمية 100%:</b>\n"
        f"• لا يظهر اسمك أو معرفك في أي مكان داخل القناة.\n"
        f"• بياناتك مشفرة ولا يمكن لأي مشرف الوصول إليها.\n\n"
        f"✍️ <b>كيفية الاستخدام:</b>\n"
        f"• أرسل سؤالك أو استفسارك مباشرة هنا (نص أو وسائط) وسيتم نشره تلقائياً في القناة بعد فحصه.\n"
        f"• للرد على أي منشور، اضغط زر «💬 رد مجهول» في القناة وتابع التعليمات."
    )
    await message.answer(welcome_text, parse_mode="HTML")


@router.callback_query(F.data == "check_membership")
async def callback_check_membership(
    callback: CallbackQuery,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings
):
    """إعادة فحص اشتراك الطالب عند ضغط زر التحقق"""
    user = callback.from_user
    if not user:
        return

    is_member, _ = await check_channel_membership(bot, settings.channel_id, user.id)  # (bot, channel_id, user_id)
    if is_member or user.id in settings.admin_ids:
        student = await db.get_or_create_student(user.id, user.full_name, user.username)
        await callback.message.edit_text(
            f"✅ <b>تم التحقق من عضويتك بنجاح!</b>\n\n"
            f"🎭 <b>رقمك المجهول هو:</b> <code>طالب #{student.anonymous_id}</code>\n\n"
            f"يمكنك الآن إرسال أسئلتك واستفساراتك مباشرة هنا وسيتم نشرها في القناة بهوية مجهولة.",
            parse_mode="HTML"
        )
    else:
        await callback.answer(
            "❌ لم يتم العثور على عضويتك في القناة بعد! يرجى الانضمام أولاً.",
            show_alert=True
        )


@router.message(Command("my_id"))
async def handle_my_id_command(message: Message, db: DatabaseManager):
    """عرض الرقم المجهول وإحصائيات الطالب"""
    user = message.from_user
    if not user:
        return

    student = await db.get_student_by_telegram_id(user.id)
    if not student:
        student = await db.get_or_create_student(
            telegram_id=user.id,
            full_name=user.full_name,
            username=user.username
        )

    # حالة الحساب
    status_str = "🟢 نشط وغير محظور"
    if student.is_banned:
        status_str = f"🔴 محظور من النشر (السبب: {student.ban_reason or 'مخالفة السياسة'})"
    else:
        is_muted, rem_mins = db.is_student_muted(student)
        if is_muted:
            status_str = f"⏳ موقوف مؤقتاً ({rem_mins} دقيقة متبقية)"

    info_text = (
        f"🎭 <b>بطاقتك الطلابية المجهولة:</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔢 <b>معرفك المجهول:</b> <code>طالب #{student.anonymous_id}</code>\n"
        f"📊 <b>إجمالي أسئلتك المنشورة:</b> {student.total_posts}\n"
        f"💬 <b>إجمالي ردودك المنشورة:</b> {student.total_replies}\n"
        f"⚡ <b>حالة الحساب:</b> {status_str}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"<i>هذا الرقم هو هويتك الثابتة في القناة لحفظ حقوق مشاركاتك ومصداقيتك.</i>"
    )
    await message.answer(info_text, parse_mode="HTML")


@router.message(Command("rules"))
async def handle_rules_command(message: Message):
    """عرض قوانين وضوابط النشر في القناة"""
    rules_text = (
        f"📜 <b>ضوابط وقوانين النشر في القناة الطلابية:</b>\n\n"
        f"1️⃣ <b>الهدف التعليمي والأكاديمي:</b> القناة مخصصة حصراً للأسئلة والنقاشات الدراسية والجامعية.\n"
        f"2️⃣ <b>الاحترام المتبادل:</b> يُمنع منعاً باتاً أي شتائم أو تنمر أو إساءة شخصية للزملاء أو الدكاترة.\n"
        f"3️⃣ <b>الخصوصية والأمان:</b> يُمنع نشر أي أرقام هواتف، إيميلات، أو روابط خارجية مشبوهة أو ترويجية.\n"
        f"4️⃣ <b>عدم التكرار والإغراق:</b> يرجى عدم تكرار نفس السؤال أكثر من مرة خلال فترة وجيزة.\n"
        f"5️⃣ <b>الرقابة الصارمة:</b> جميع الرسائل تمر على نظام فحص آلي دقيق، وتكرار المخالفات يؤدي للكتم أو الحظر الدائم."
    )
    await message.answer(rules_text, parse_mode="HTML")


@router.message(Command("cancel"))
async def handle_cancel_command(message: Message, state: FSMContext):
    """إلغاء أي عملية رد أو إرسال حالية"""
    current_state = await state.get_state()
    if current_state:
        await state.clear()
        await message.answer("✅ تم إلغاء العملية بنجاح. يمكنك الآن إرسال سؤال جديد في أي وقت.")
    else:
        await message.answer("ℹ️ لا توجد أي عملية نشطة لإلغائها.")


@router.message(Command("help"))
async def handle_help_command(message: Message):
    """دليل المساعدة واستخدام البوت"""
    help_text = (
        f"💡 <b>دليل استخدام البوت:</b>\n\n"
        f"• <b>إرسال سؤال:</b> اكتب رسالتك مباشرة هنا أو أرسل صورة/ملفاً/تسجيلاً صوتياً.\n"
        f"• <b>الرد على سؤال:</b> اضغط على زر «💬 رد مجهول» الموجود أسفل أي منشور في القناة، ثم اكتب ردك في البوت.\n"
        f"• <b>الخصوصية:</b> كل مشاركاتك تظهر برقم مجهول ثابت (مثل طالب #101) لحماية هويتك بالكامل."
    )
    await message.answer(help_text, parse_mode="HTML")

@router.message(Command("forget_me"))
async def handle_forget_me_command(message: Message, db: DatabaseManager):
    """طلب حذف وتطهير البيانات الشخصية مع تأكيد صريح (GDPR/Right to be Forgotten)"""
    user = message.from_user
    if not user:
        return

    student = await db.get_student_by_telegram_id(user.id)
    if not student:
        await message.answer("ℹ️ لا توجد بيانات مسجلة لحسابك حالياً.")
        return

    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="✅ نعم، احذف بياناتي نهائياً", callback_data="confirm_forget_me"),
                InlineKeyboardButton(text="❌ إلغاء", callback_data="cancel_forget_me")
            ]
        ]
    )

    await message.answer(
        "⚠️ <b>تأكيد طلب حذف البيانات الشخصية (GDPR)</b>\n\n"
        "هل أنت متأكد من رغبتك في تطهير ومسح كافة بيانات هويتك الشخصية المشفرة؟\n"
        "<i>ملاحظة: هذا الإجراء نهائي ولا يمكن التراجع عنه.</i>",
        reply_markup=kb,
        parse_mode="HTML"
    )


@router.callback_query(F.data == "confirm_forget_me")
async def handle_confirm_forget_me(callback: CallbackQuery, db: DatabaseManager):
    """تأكيد تطهير البيانات ومسح الهوية الشخصية"""
    user = callback.from_user
    if not user:
        return

    student = await db.get_student_by_telegram_id(user.id)
    if not student:
        await callback.message.edit_text("ℹ️ لم يتم العثور على بيانات نشطة لمسحها.")
        await callback.answer()
        return

    await db.wipe_student_data(student.anonymous_id)
    await callback.message.edit_text(
        "🛡️ <b>تم تطهير وحذف بياناتك الشخصية بنجاح!</b>\n\n"
        "تم مسح كافة البيانات المشفرة المرتبطة بحسابك في تيليجرام من قاعدة البيانات وفقاً لسياسة الخصوصية وحق النسيان.",
        parse_mode="HTML"
    )
    await callback.answer("تم مسح بياناتك بنجاح")


@router.callback_query(F.data == "cancel_forget_me")
async def handle_cancel_forget_me(callback: CallbackQuery):
    """إلغاء طلب حذف البيانات"""
    await callback.message.edit_text("✅ تم إلغاء عملية حذف البيانات بنجاح.")
    await callback.answer("تم الإلغاء")

