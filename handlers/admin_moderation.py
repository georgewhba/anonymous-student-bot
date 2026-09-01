"""
Admin Moderation Handlers.
Enforces strict server-side RBAC:
- WHOIS, Wipe Student, Broadcast: STRICTLY Primary Admin.
- Ban, Unban, Mute, Unmute, Delete: Allowed for Staff (Primary Admin & Moderators).
"""
import asyncio
from typing import Optional, Any, Callable, Dict, Awaitable
from aiogram import Router, Bot, BaseMiddleware
from aiogram.filters import Command
from aiogram.types import Message, TelegramObject

from database.db_manager import DatabaseManager
from database.models import StudentModel
from config import Settings
from filters.admin_filter import IsAdmin
from security.auth import admin_session_manager, is_admin_session_valid
from security.identity_vault import IdentityVault, DecryptedIdentity
from security.escaping import escape_user_content
from utils.logger import logger, send_admin_log_notification

router = Router(name="admin_moderation")
router.message.filter(IsAdmin())


class AdminAuthMiddleware(BaseMiddleware):
    """وسيط أمني للتأكد من تسجيل دخول المشرف بكلمة المرور قبل تنفيذ أي أمر رقابي"""
    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any]
    ) -> Any:
        settings: Settings = data.get("settings")
        if isinstance(event, Message) and event.from_user and settings:
            if not is_admin_session_valid(event.from_user.id, settings):
                await event.answer(
                    "🔒 <b>لوحة التحكم مقفلة!</b>\n"
                    "يرجى إرسال أمر <code>/admin</code> وكتابة كلمة المرور الخاصة بك أولاً لتفعيل الجلسة.",
                    parse_mode="HTML"
                )
                return None
        return await handler(event, data)


router.message.middleware(AdminAuthMiddleware())


async def execute_whois_lookup(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings,
    query_str: str
):
    """تنفيذ البحث عن هوية الطالب المشفرة (حصراً للمسؤول الأساسي)"""
    user_id = message.from_user.id if message.from_user else 0

    # 1. فحص الصلاحيات من جانب الخادم (Server-Side RBAC)
    if not admin_session_manager.is_primary_admin(user_id, settings):
        await message.answer(
            "⛔ <b>غير مصرح:</b> كشف الهوية المشفرة متاح حصرياً للمسؤول الأساسي (Primary Admin).",
            parse_mode="HTML"
        )
        return

    query_clean = query_str.strip().lstrip("#")
    if not query_clean.isdigit():
        await message.answer("⚠️ يرجى إدخال رقم صحيح (مثل: <code>/whois 154</code> أو <code>/whois 342</code>).", parse_mode="HTML")
        return

    target_num = int(query_clean)
    student: Optional[StudentModel] = None
    extra_context = ""

    # أولاً: فحص هل الرقم هو معرف رسالة في القناة
    found_by_msg = await db.find_author_by_channel_message_id(target_num)
    if found_by_msg:
        student, extra_context, preview = found_by_msg
        safe_prev = escape_user_content(preview[:100])
        extra_context = f"\n📌 <b>الرسالة المستهدفة:</b> {extra_context}\n📝 <b>محتوى الرسالة:</b> <i>\"{safe_prev}\"</i>\n"
        post_obj = await db.get_post_by_channel_msg_id(target_num)
        reply_obj = await db.get_reply_by_channel_msg_id(target_num)
        enc_fn = (post_obj.enc_original_filename if post_obj else None) or (reply_obj.enc_original_filename if reply_obj else None)
        if enc_fn:
            orig_fn = IdentityVault.decrypt_filename(enc_fn, db.crypto, user_id, settings)
            if orig_fn:
                safe_fn = escape_user_content(orig_fn)
                extra_context += f"📁 <b>اسم الملف الأصلي:</b> <code>{safe_fn}</code>\n"
    else:
        # ثانياً: البحث المباشر بالرقم المجهول
        student = await db.get_student_by_anonymous_id(target_num)

    if not student:
        await message.answer(
            f"❌ لم يتم العثور على أي طالب أو منشور مرتبط بالرقم <b>#{target_num}</b>.",
            parse_mode="HTML"
        )
        return

    # فك تشفير الهوية عبر خزنة الهوية الآمنة
    try:
        identity: DecryptedIdentity = IdentityVault.resolve_student_identity(
            student=student,
            crypto=db.crypto,
            requesting_user_id=user_id,
            settings=settings
        )
    except PermissionError as pe:
        await message.answer(f"⛔ {pe}", parse_mode="HTML")
        return

    # حالة الحظر والكتم
    status_text = "🟢 نشط (غير محظور)"
    if identity.is_banned:
        status_text = f"🔴 محظور (السبب: {identity.ban_reason or 'بدون سبب'})"
    else:
        is_muted, rem_mins = db.is_student_muted(student)
        if is_muted:
            status_text = f"⏳ موقوف مؤقتاً ({rem_mins} دقيقة متبقية)"

    user_link = f"@{identity.username}" if identity.username else "لا يوجد معرف"
    created_date = identity.created_at[:10] if identity.created_at else "غير معروف"
    last_active = identity.last_active_at[:16].replace("T", " ") if identity.last_active_at else "غير معروف"

    response_text = (
        f"🔍 <b>كشف الهوية المشفرة للطالب (Primary Admin Only)</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🎭 <b>الرقم المجهول:</b> <code>طالب #{identity.anonymous_id}</code>\n"
        f"👤 <b>الاسم الحقيقي:</b> <code>{escape_user_content(identity.full_name) or 'مجهول'}</code>\n"
        f"🔗 <b>اسم المستخدم:</b> {user_link}\n"
        f"🆔 <b>Telegram ID:</b> <code>{identity.telegram_id}</code>\n"
        f"{extra_context}"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"📅 <b>تاريخ التسجيل:</b> {created_date}\n"
        f"⏰ <b>آخر تفاعل:</b> {last_active}\n"
        f"📊 <b>إجمالي المشاركات:</b> {identity.total_posts} أسئلة | {identity.total_replies} ردود\n"
        f"⚡ <b>حالة الحساب:</b> {status_text}"
    )

    # تسجيل الإجراء في سجل الرقابة بدون تسريب PII
    await db.log_audit_action(
        admin_id=user_id,
        action="WHOIS",
        target_anonymous_id=identity.anonymous_id,
        details=f"استعلام هوية طالب #{identity.anonymous_id}"
    )

    await send_admin_log_notification(
        bot,
        settings.admin_log_channel_id,
        f"🔍 <b>كشف هوية طالب</b>\nالهدف: <code>طالب #{identity.anonymous_id}</code>"
    )

    await message.answer(response_text, parse_mode="HTML")


@router.message(Command("whois"))
async def handle_whois_command(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings
):
    """أمر كشف هوية الطالب: /whois <رقم_الطالب_أو_المنشور> (Primary Admin فقط)"""
    args = message.text.split(maxsplit=1) if message.text else []
    if len(args) < 2:
        await message.answer(
            "⚠️ <b>طريقة الاستخدام:</b>\n"
            "<code>/whois 154</code> (برقم الطالب المجهول)\n"
            "<code>/whois #342</code> (برقم المنشور في القناة)",
            parse_mode="HTML"
        )
        return

    await execute_whois_lookup(message, bot, db, settings, args[1])


@router.message(Command("ban"))
async def handle_ban_command(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings
):
    """حظر طالب نهائياً: /ban <رقم_الطالب> [السبب] (Staff)"""
    parts = message.text.split(maxsplit=2) if message.text else []
    if len(parts) < 2 or not parts[1].lstrip("#").isdigit():
        await message.answer("⚠️ طريقة الاستخدام: <code>/ban 154 مخالفة القوانين</code>", parse_mode="HTML")
        return

    anon_id = int(parts[1].lstrip("#"))
    reason = parts[2] if len(parts) > 2 else "مخالفة ضوابط القناة"

    student = await db.get_student_by_anonymous_id(anon_id)
    if not student:
        await message.answer(f"❌ لم يتم العثور على طالب بالرقم #{anon_id}.")
        return

    success = await db.ban_student(anon_id, reason)
    if success:
        await db.log_audit_action(
            admin_id=message.from_user.id,
            action="BAN",
            target_anonymous_id=anon_id,
            details=f"تم حظر الطالب #{anon_id} نهائياً. السبب: {reason}"
        )

        await send_admin_log_notification(
            bot,
            settings.admin_log_channel_id,
            f"🚫 <b>حظر طالب</b>\n"
            f"الطالب: <code>طالب #{anon_id}</code>\n"
            f"السبب: <i>{escape_user_content(reason)}</i>"
        )

        # إشعار الطالب عبر الخاص إن أمكن دون كشف هويته للمشرف
        await IdentityVault.send_system_notification(
            bot=bot,
            student=student,
            crypto=db.crypto,
            text=f"🚫 <b>تنبيه إداري:</b> تم حظرك من النشر في القناة.\nالسبب: <i>{escape_user_content(reason)}</i>",
            parse_mode="HTML"
        )

        await message.answer(
            f"✅ <b>تم حظر الطالب #{anon_id} بنجاح.</b>\nالسبب: {escape_user_content(reason)}",
            parse_mode="HTML"
        )
    else:
        await message.answer("❌ فشل تنفيذ الحظر.")


@router.message(Command("unban"))
async def handle_unban_command(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings
):
    """إلغاء حظر طالب: /unban <رقم_الطالب> (Staff)"""
    parts = message.text.split() if message.text else []
    if len(parts) < 2 or not parts[1].lstrip("#").isdigit():
        await message.answer("⚠️ طريقة الاستخدام: <code>/unban 154</code>", parse_mode="HTML")
        return

    anon_id = int(parts[1].lstrip("#"))
    student = await db.get_student_by_anonymous_id(anon_id)
    if not student:
        await message.answer(f"❌ لم يتم العثور على طالب بالرقم #{anon_id}.")
        return

    success = await db.unban_student(anon_id)
    if success:
        await db.log_audit_action(
            admin_id=message.from_user.id,
            action="UNBAN",
            target_anonymous_id=anon_id,
            details=f"تم إلغاء حظر الطالب #{anon_id}"
        )

        await send_admin_log_notification(
            bot,
            settings.admin_log_channel_id,
            f"✅ <b>إلغاء حظر طالب</b>\nالطالب: <code>طالب #{anon_id}</code>"
        )

        await IdentityVault.send_system_notification(
            bot=bot,
            student=student,
            crypto=db.crypto,
            text="✅ <b>تم إلغاء حظرك!</b> يمكنك الآن إرسال الأسئلة والمشاركات مجدداً.",
            parse_mode="HTML"
        )

        await message.answer(f"✅ تم إلغاء حظر الطالب #{anon_id} بنجاح.")
    else:
        await message.answer("❌ فشل إلغاء الحظر.")


@router.message(Command("mute"))
async def handle_mute_command(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings
):
    """كتم طالب مؤقتاً: /mute <رقم_الطالب> <المدة_بالدقائق> (Staff)"""
    parts = message.text.split() if message.text else []
    if len(parts) < 3 or not parts[1].lstrip("#").isdigit() or not parts[2].isdigit():
        await message.answer("⚠️ طريقة الاستخدام: <code>/mute 154 60</code> (كتم لمدة 60 دقيقة)", parse_mode="HTML")
        return

    anon_id = int(parts[1].lstrip("#"))
    duration = int(parts[2])

    student = await db.get_student_by_anonymous_id(anon_id)
    if not student:
        await message.answer(f"❌ لم يتم العثور على طالب بالرقم #{anon_id}.")
        return

    res = await db.mute_student(anon_id, duration)
    if res:
        await db.log_audit_action(
            admin_id=message.from_user.id,
            action="MUTE",
            target_anonymous_id=anon_id,
            details=f"تم كتم الطالب #{anon_id} لمدة {duration} دقيقة"
        )

        await send_admin_log_notification(
            bot,
            settings.admin_log_channel_id,
            f"⏳ <b>كتم مؤقت لطالب</b>\nالطالب: <code>طالب #{anon_id}</code>\nالمدة: <b>{duration}</b> دقيقة"
        )

        await IdentityVault.send_system_notification(
            bot=bot,
            student=student,
            crypto=db.crypto,
            text=f"⏳ <b>تنبيه إداري:</b> تم إيقافك مؤقتاً عن النشر لمدة <b>{duration}</b> دقيقة.",
            parse_mode="HTML"
        )

        await message.answer(f"✅ تم كتم الطالب #{anon_id} لمدة <b>{duration}</b> دقيقة بنجاح.", parse_mode="HTML")
    else:
        await message.answer("❌ فشل تنفيذ الكتم.")


@router.message(Command("unmute"))
async def handle_unmute_command(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings
):
    """إلغاء كتم طالب: /unmute <رقم_الطالب> (Staff)"""
    parts = message.text.split() if message.text else []
    if len(parts) < 2 or not parts[1].lstrip("#").isdigit():
        await message.answer("⚠️ طريقة الاستخدام: <code>/unmute 154</code>", parse_mode="HTML")
        return

    anon_id = int(parts[1].lstrip("#"))
    student = await db.get_student_by_anonymous_id(anon_id)
    if not student:
        await message.answer(f"❌ لم يتم العثور على طالب بالرقم #{anon_id}.")
        return

    success = await db.unmute_student(anon_id)
    if success:
        await db.log_audit_action(
            admin_id=message.from_user.id,
            action="UNMUTE",
            target_anonymous_id=anon_id,
            details=f"تم إلغاء كتم الطالب #{anon_id}"
        )

        await send_admin_log_notification(
            bot,
            settings.admin_log_channel_id,
            f"🔊 <b>إلغاء كتم طالب</b>\nالطالب: <code>طالب #{anon_id}</code>"
        )

        await IdentityVault.send_system_notification(
            bot=bot,
            student=student,
            crypto=db.crypto,
            text="🔊 <b>تم إلغاء الكتم عن حسابك.</b> يمكنك النشر والمشاركة الآن.",
            parse_mode="HTML"
        )

        await message.answer(f"✅ تم إلغاء كتم الطالب #{anon_id} بنجاح.")
    else:
        await message.answer("❌ فشل إلغاء الكتم.")


@router.message(Command("del"))
async def handle_delete_command(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings
):
    """حذف رسالة أو منشور من القناة: /del <رقم_الرسالة_في_القناة> (Staff)"""
    parts = message.text.split() if message.text else []
    if len(parts) < 2 or not parts[1].lstrip("#").isdigit():
        await message.answer("⚠️ طريقة الاستخدام: <code>/del 342</code> (رقم الرسالة في القناة)", parse_mode="HTML")
        return

    msg_id = int(parts[1].lstrip("#"))

    try:
        from moderation.publisher import publisher_service
        deleted = await publisher_service.delete_channel_message(bot, settings.channel_id, msg_id)
        if not deleted:
            await message.answer("❌ تعذر حذف الرسالة. تأكد من أن الرسالة موجودة وأن البوت يمتلك صلاحية الحذف.")
            return

        await db.delete_post_from_db(msg_id)

        await db.log_audit_action(
            admin_id=message.from_user.id,
            action="DELETE_POST",
            details=f"تم حذف الرسالة #{msg_id} من القناة"
        )

        await send_admin_log_notification(
            bot,
            settings.admin_log_channel_id,
            f"🗑️ <b>حذف رسالة من القناة</b>\nرقم الرسالة: <code>#{msg_id}</code>"
        )

        await message.answer(f"✅ تم حذف المنشور #{msg_id} من القناة بنجاح.")
    except Exception as e:
        logger.error(f"خطأ أثناء حذف الرسالة {msg_id}: {e}")
        await message.answer("❌ تعذر حذف الرسالة. تأكد من أن الرسالة موجودة وأن البوت يمتلك صلاحية الحذف.")


@router.message(Command("wipe_student"))
async def handle_wipe_student_command(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings
):
    """تطهير بيانات طالب نهائياً بناءً على طلب الخصوصية: /wipe_student <رقم_الطالب> (Primary Admin فقط)"""
    user_id = message.from_user.id if message.from_user else 0
    if not admin_session_manager.is_primary_admin(user_id, settings):
        await message.answer("⛔ <b>غير مصرح:</b> تطهير بيانات الطلاب متاح حصرياً للمسؤول الأساسي (Primary Admin).", parse_mode="HTML")
        return

    parts = message.text.split() if message.text else []
    if len(parts) < 2 or not parts[1].lstrip("#").isdigit():
        await message.answer("⚠️ طريقة الاستخدام: <code>/wipe_student 154</code>", parse_mode="HTML")
        return

    anon_id = int(parts[1].lstrip("#"))
    student = await db.get_student_by_anonymous_id(anon_id)
    if not student:
        await message.answer(f"❌ لم يتم العثور على طالب بالرقم #{anon_id}.")
        return

    success = await db.wipe_student_data(anon_id)
    if success:
        await db.log_audit_action(
            admin_id=user_id,
            action="WIPE_STUDENT",
            target_anonymous_id=anon_id,
            details=f"تم تطهير وحذف كافة بيانات الطالب #{anon_id} نهائياً (Privacy/GDPR Wipe)"
        )

        await send_admin_log_notification(
            bot,
            settings.admin_log_channel_id,
            f"🧹 <b>تطهير بيانات طالب</b>\nالهدف: <code>طالب #{anon_id}</code> (تم محو الهوية الشخصية بالكامل)"
        )

        await message.answer(f"🛡️ تم تطهير وحذف البيانات الشخصية للطالب #{anon_id} بنجاح.")
    else:
        await message.answer("❌ فشل تطهير البيانات.")


@router.message(Command("broadcast"))
async def handle_broadcast_command(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings
):
    """إرسال إذاعة عامة لجميع الطلاب المسجلين بالبوت: /broadcast <الرسالة> (Primary Admin فقط)"""
    user_id = message.from_user.id if message.from_user else 0
    if not admin_session_manager.is_primary_admin(user_id, settings):
        await message.answer("⛔ <b>غير مصرح:</b> الإذاعة العامة متاحة حصرياً للمسؤول الأساسي (Primary Admin).", parse_mode="HTML")
        return

    args = message.text.split(maxsplit=1) if message.text else []
    if len(args) < 2:
        await message.answer("⚠️ طريقة الاستخدام: <code>/broadcast نص الرسالة أو التنبيه هنا</code>", parse_mode="HTML")
        return

    broadcast_text = escape_user_content(args[1])
    status_msg = await message.answer("⏳ جاري بدء إرسال الإذاعة لجميع الطلاب المسجلين...")

    # نستخدم DatabaseManager الرسمي بدلاً من فتح SQLite مباشر لضمان سلامة المتزامن
    rows = await db.get_all_active_student_enc_ids()

    success_count = 0
    fail_count = 0

    for (enc_tid,) in rows:
        stub = type("StudentStub", (), {"enc_telegram_id": enc_tid})()
        sent = await IdentityVault.send_system_notification(
            bot=bot,
            student=stub,
            crypto=db.crypto,
            text=f"📢 <b>إعلان رسمي من إدارة القناة</b>\n━━━━━━━━━━━━━━━━━━\n\n{broadcast_text}",
            parse_mode="HTML"
        )
        if sent:
            success_count += 1
            # 0.1s = 10 رسائل/ثانية — آمن بشكل مريح عن حد 30/ثانية لـ Telegram
            await asyncio.sleep(0.1)
        else:
            fail_count += 1

    await status_msg.edit_text(
        f"✅ <b>اكتملت الإذاعة بنجاح!</b>\n\n"
        f"• 📨 <b>تم الإرسال بنجاح إلى:</b> {success_count} طالب\n"
        f"• ⚠️ <b>فشل الإرسال إلى:</b> {fail_count} طالب",
        parse_mode="HTML"
    )
