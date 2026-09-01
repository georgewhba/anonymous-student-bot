"""
Admin Panel and Dashboard Handler.
Handles 2FA login, role-based dashboards, submission toggling, and log reviews.
"""
from aiogram import Router, F, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.context import FSMContext

from database.db_manager import DatabaseManager
from config import Settings
from filters.admin_filter import IsAdmin
from security.auth import (
    admin_session_manager,
    is_admin_session_valid,
    terminate_admin_session,
    get_lockout_remaining_seconds,
    hash_admin_password,
    AdminRole
)
from utils.logger import send_admin_log_notification

router = Router(name="admin_panel")
router.message.filter(IsAdmin())
router.callback_query.filter(IsAdmin())


class AdminState(StatesGroup):
    waiting_for_password = State()
    waiting_for_whois_query = State()
    waiting_for_broadcast_text = State()


def get_admin_panel_keyboard(submissions_enabled: bool, is_primary_admin: bool) -> InlineKeyboardMarkup:
    """لوحة أزرار التحكم الإدارية وفقاً لصلاحيات المستخدم (RBAC)"""
    toggle_text = "🔴 إيقاف استقبال المشاركات" if submissions_enabled else "🟢 تفعيل استقبال المشاركات"
    buttons = [
        [
            InlineKeyboardButton(text=toggle_text, callback_data="admin_toggle_submissions"),
            InlineKeyboardButton(text="🔄 تحديث البيانات", callback_data="admin_refresh_stats")
        ]
    ]

    # زر كشف الهوية متاح حصراً للمسؤول الأساسي
    if is_primary_admin:
        buttons.append([
            InlineKeyboardButton(text="🔍 كشف هوية مشاركة (WHOIS)", callback_data="admin_whois_prompt"),
            InlineKeyboardButton(text="📋 سجل الرقابة", callback_data="admin_view_logs")
        ])
        buttons.append([
            InlineKeyboardButton(text="📢 إذاعة عامة للطلاب", callback_data="admin_broadcast_prompt"),
            InlineKeyboardButton(text="📖 دليل الأوامر", callback_data="admin_commands_guide")
        ])
    else:
        buttons.append([
            InlineKeyboardButton(text="📋 سجل الرقابة", callback_data="admin_view_logs"),
            InlineKeyboardButton(text="📖 دليل الأوامر", callback_data="admin_commands_guide")
        ])

    buttons.append([
        InlineKeyboardButton(text="🔒 قفل اللوحة (تسجيل الخروج)", callback_data="admin_logout")
    ])

    return InlineKeyboardMarkup(inline_keyboard=buttons)


@router.message(Command("admin"))
async def handle_admin_panel_command(
    message: Message,
    db: DatabaseManager,
    settings: Settings,
    state: FSMContext
):
    """عرض لوحة تحكم المشرفين الرئيسية بعد التحقق من كلمة المرور"""
    user = message.from_user
    if not user:
        return

    # التحقق هل جلسة المشرف موثقة وسارية؟
    if not is_admin_session_valid(user.id, settings):
        await state.set_state(AdminState.waiting_for_password)
        await message.answer(
            "🔐 <b>لوحة تحكم المشرفين محمية بنظام التحقق الثنائي (2FA)</b>\n"
            "━━━━━━━━━━━━━━━━━━\n\n"
            "يرجى إدخال <b>كلمة مرور الإدارة (Admin Password)</b> للمتابعة:\n"
            "<i>(سيتم حذف رسالة كلمة المرور فوراً من المحادثة لأمان تام)</i>\n\n"
            "❌ <i>أو أرسل /cancel للإلغاء</i>",
            parse_mode="HTML"
        )
        return

    await show_admin_dashboard(message, db, settings, state, user.id)


@router.message(AdminState.waiting_for_password)
async def handle_admin_password_input(
    message: Message,
    db: DatabaseManager,
    settings: Settings,
    state: FSMContext
):
    """معالجة والتحقق من كلمة مرور المشرف وحذف الرسالة فوراً"""
    user = message.from_user
    if not user:
        return

    entered_password = message.text or ""

    # حذف رسالة كلمة المرور فوراً من شات تيليجرام
    try:
        await message.delete()
    except Exception:
        pass

    if entered_password.strip() == "/cancel":
        await state.clear()
        await message.answer("❌ تم إلغاء تسجيل الدخول.")
        return

    # التحقق من كلمة المرور الفردية أو العامة
    cred = await db.get_admin_credential(user.id)
    custom_hash = cred[0] if cred else None
    is_authenticated, error_msg = admin_session_manager.authenticate(
        user.id, entered_password, settings, custom_password_hash=custom_hash
    )

    if is_authenticated:
        await state.clear()
        role = admin_session_manager.get_role_for_user(user.id, settings)
        role_name = "المسؤول الأساسي (Primary Admin)" if role == AdminRole.PRIMARY_ADMIN else "مشرف (Moderator)"
        await message.answer(
            f"✅ <b>تم التحقق وتوثيق هويتك بنجاح!</b>\n"
            f"الدور المصرح: <b>{role_name}</b>",
            parse_mode="HTML"
        )
        await show_admin_dashboard(message, db, settings, state, user.id)
    else:
        lockout_secs = get_lockout_remaining_seconds(user.id)
        if lockout_secs > 0:
            lockout_mins = max(1, lockout_secs // 60)
            await message.answer(
                f"🔒 <b>تم قفل الحساب مؤقتاً!</b>\n"
                f"تجاوزت الحد المسموح من المحاولات الخاطئة.\n"
                f"يرجى الانتظار <b>{lockout_mins} دقيقة</b> قبل المحاولة مجدداً.",
                parse_mode="HTML"
            )
        else:
            await message.answer(
                f"❌ <b>{error_msg or 'كلمة المرور غير صحيحة!'}</b>\n"
                "يرجى إعادة المحاولة:",
                parse_mode="HTML"
            )


async def show_admin_dashboard(
    target: Message,
    db: DatabaseManager,
    settings: Settings,
    state: FSMContext,
    user_id: int
):
    """بناء وعرض لوحة التحكم وفق صلاحيات المشرف"""
    await state.clear()
    stats = await db.get_statistics()
    status_icon = "🟢 مفعل" if stats["submissions_enabled"] else "🔴 متوقف"
    is_primary = admin_session_manager.is_primary_admin(user_id, settings)

    role_label = "👑 المسؤول الأساسي" if is_primary else "🛡️ مشرف"

    text = (
        f"👑 <b>لوحة تحكم إدارة القناة والبوت</b> ({role_label})\n"
        f"━━━━━━━━━━━━━━━━━━\n\n"
        f"📊 <b>إحصائيات النظام:</b>\n"
        f"• 👥 <b>إجمالي الطلاب المسجلين:</b> {stats['total_students']}\n"
        f"• 📝 <b>إجمالي الأسئلة المنشورة:</b> {stats['total_posts']}\n"
        f"• 💬 <b>إجمالي الردود المجهولة:</b> {stats['total_replies']}\n"
        f"• 🚫 <b>الطلاب المحظورين:</b> {stats['banned_students']}\n"
        f"• ⚡ <b>استقبال المشاركات:</b> {status_icon}\n\n"
        f"👇 <i>اختر إجراءً من الأزرار أدناه:</i>"
    )

    await target.answer(
        text,
        parse_mode="HTML",
        reply_markup=get_admin_panel_keyboard(stats["submissions_enabled"], is_primary)
    )


@router.callback_query(F.data == "admin_logout")
async def callback_admin_logout(callback: CallbackQuery):
    """إقفال جلسة المشرف وتسجيل الخروج"""
    user_id = callback.from_user.id
    terminate_admin_session(user_id)
    await callback.message.edit_text(
        "🔒 <b>تم إقفال لوحة التحكم وتسجيل الخروج بنجاح!</b>\n"
        "للدخول مجدداً، أرسل أمر <code>/admin</code> وأدخل كلمة المرور.",
        parse_mode="HTML"
    )
    await callback.answer("تم تسجيل الخروج 🔒", show_alert=True)


@router.callback_query(F.data == "admin_refresh_stats")
async def callback_refresh_stats(
    callback: CallbackQuery,
    db: DatabaseManager,
    settings: Settings
):
    """تحديث إحصائيات لوحة التحكم"""
    user_id = callback.from_user.id
    if not is_admin_session_valid(user_id, settings):
        await callback.answer("🔒 الجلسة منتهية، يرجى كتابة /admin وتسجيل الدخول مجدداً.", show_alert=True)
        return

    stats = await db.get_statistics()
    status_icon = "🟢 مفعل" if stats["submissions_enabled"] else "🔴 متوقف"
    is_primary = admin_session_manager.is_primary_admin(user_id, settings)
    role_label = "👑 المسؤول الأساسي" if is_primary else "🛡️ مشرف"

    text = (
        f"👑 <b>لوحة تحكم إدارة القناة والبوت</b> ({role_label})\n"
        f"━━━━━━━━━━━━━━━━━━\n\n"
        f"📊 <b>إحصائيات النظام:</b>\n"
        f"• 👥 <b>إجمالي الطلاب المسجلين:</b> {stats['total_students']}\n"
        f"• 📝 <b>إجمالي الأسئلة المنشورة:</b> {stats['total_posts']}\n"
        f"• 💬 <b>إجمالي الردود المجهولة:</b> {stats['total_replies']}\n"
        f"• 🚫 <b>الطلاب المحظورين:</b> {stats['banned_students']}\n"
        f"• ⚡ <b>استقبال المشاركات:</b> {status_icon}\n\n"
        f"👇 <i>اختر إجراءً من الأزرار أدناه:</i>"
    )

    await callback.message.edit_text(
        text,
        parse_mode="HTML",
        reply_markup=get_admin_panel_keyboard(stats["submissions_enabled"], is_primary)
    )
    await callback.answer("تم تحديث البيانات ✅")


@router.callback_query(F.data == "admin_toggle_submissions")
async def callback_toggle_submissions(
    callback: CallbackQuery,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings
):
    """تبديل حالة استقبال الأسئلة (تشغيل / إيقاف)"""
    user_id = callback.from_user.id
    if not is_admin_session_valid(user_id, settings):
        await callback.answer("🔒 الجلسة منتهية، يرجى كتابة /admin وتسجيل الدخول مجدداً.", show_alert=True)
        return

    current_val = await db.get_system_setting("submissions_enabled", "true")
    new_val = "false" if current_val == "true" else "true"
    await db.set_system_setting("submissions_enabled", new_val)

    action_label = "تفعيل" if new_val == "true" else "إيقاف"
    await db.log_audit_action(
        admin_id=user_id,
        action="TOGGLE_SUBMISSIONS",
        details=f"تم {action_label} استقبال الأسئلة والمشاركات"
    )

    await send_admin_log_notification(
        bot,
        settings.admin_log_channel_id,
        f"⚙️ <b>تغيير حالة النظام</b>\nقام المشرف بتنفيذ: <b>{action_label}</b> استقبال الأسئلة."
    )

    stats = await db.get_statistics()
    status_icon = "🟢 مفعل" if stats["submissions_enabled"] else "🔴 متوقف"
    is_primary = admin_session_manager.is_primary_admin(user_id, settings)

    text = (
        f"👑 <b>لوحة تحكم إدارة القناة والبوت</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n\n"
        f"📊 <b>إحصائيات النظام:</b>\n"
        f"• 👥 <b>إجمالي الطلاب المسجلين:</b> {stats['total_students']}\n"
        f"• 📝 <b>إجمالي الأسئلة المنشورة:</b> {stats['total_posts']}\n"
        f"• 💬 <b>إجمالي الردود المجهولة:</b> {stats['total_replies']}\n"
        f"• 🚫 <b>الطلاب المحظورين:</b> {stats['banned_students']}\n"
        f"• ⚡ <b>استقبال المشاركات:</b> {status_icon}\n\n"
        f"⚠️ <i>تم {action_label} استقبال الأسئلة بنجاح!</i>"
    )

    await callback.message.edit_text(
        text,
        parse_mode="HTML",
        reply_markup=get_admin_panel_keyboard(stats["submissions_enabled"], is_primary)
    )
    await callback.answer(f"تم {action_label} استقبال المشاركات")


@router.callback_query(F.data == "admin_view_logs")
async def callback_view_logs(
    callback: CallbackQuery,
    db: DatabaseManager,
    settings: Settings
):
    """عرض أحدث سجلات المشرفين بدون تسريب بيانات PII"""
    if not is_admin_session_valid(callback.from_user.id, settings):
        await callback.answer("🔒 الجلسة منتهية، يرجى كتابة /admin وتسجيل الدخول مجدداً.", show_alert=True)
        return

    logs = await db.get_recent_audit_logs(limit=10)
    if not logs:
        await callback.answer("لا توجد سجلات مسجلة حتى الآن.", show_alert=True)
        return

    text = "📋 <b>أحدث 10 إجراءات في سجل الرقابة:</b>\n━━━━━━━━━━━━━━━━━━\n\n"
    for log in logs:
        target_str = f" (طالب #{log.target_anonymous_id})" if log.target_anonymous_id else ""
        text += (
            f"• <b>[{log.action}]</b>{target_str}\n"
            f"  التفاصيل: {log.details}\n"
            f"  التوقيت: {log.created_at[:16].replace('T', ' ')}\n\n"
        )

    back_kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🔙 العودة للوحة التحكم", callback_data="admin_refresh_stats")
    ]])

    await callback.message.edit_text(text, parse_mode="HTML", reply_markup=back_kb)


@router.callback_query(F.data == "admin_commands_guide")
async def callback_commands_guide(callback: CallbackQuery, settings: Settings):
    """عرض دليل الأوامر الإدارية وفق صلاحيات المستخدم"""
    is_primary = admin_session_manager.is_primary_admin(callback.from_user.id, settings)

    text = "🛡️ <b>دليل الأوامر الإدارية:</b>\n━━━━━━━━━━━━━━━━━━\n\n"

    if is_primary:
        text += (
            "👑 <b>صلاحيات المسؤول الأساسي فقط (Primary Admin):</b>\n"
            "• <code>/whois 154</code> - كشف هوية الطالب بالرقم المجهول\n"
            "• <code>/whois #342</code> - كشف هوية صاحب منشور بالقناة\n"
            "• <code>/dm 154 نص الرسالة</code> - مراسلة خاصة مجهولة للطالب\n"
            "• <code>/wipe_student 154</code> - تطهير بيانات الطالب الشخصية (GDPR)\n"
            "• <code>/broadcast نص الإذاعة</code> - إرسال إذاعة عامة للطلاب\n\n"
        )

    text += (
        "🛡️ <b>صلاحيات المشرفين العامة (Moderators):</b>\n"
        "• <code>/ban 154 سبب الحظر</code> - حظر طالب نهائياً\n"
        "• <code>/unban 154</code> - إلغاء حظر طالب\n"
        "• <code>/mute 154 60</code> - كتم طالب مؤقتاً (بالدقائق)\n"
        "• <code>/unmute 154</code> - إلغاء الكتم\n"
        "• <code>/del 342</code> - حذف منشور أو رد من القناة"
    )

    back_kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🔙 العودة للوحة التحكم", callback_data="admin_refresh_stats")
    ]])

    await callback.message.edit_text(text, parse_mode="HTML", reply_markup=back_kb)


@router.callback_query(F.data == "admin_whois_prompt")
async def callback_whois_prompt(
    callback: CallbackQuery,
    settings: Settings,
    state: FSMContext
):
    """طلب إدخال رقم الطالب أو المنشور لكشف الهوية (Primary Admin فقط)"""
    user_id = callback.from_user.id
    if not is_admin_session_valid(user_id, settings):
        await callback.answer("🔒 الجلسة منتهية، يرجى كتابة /admin وتسجيل الدخول مجدداً.", show_alert=True)
        return

    # Server-Side RBAC
    if not admin_session_manager.is_primary_admin(user_id, settings):
        await callback.answer("⛔ غير مصرح: كشف الهوية متاح حصراً للمسؤول الأساسي (Primary Admin).", show_alert=True)
        return

    await state.set_state(AdminState.waiting_for_whois_query)
    await callback.message.answer(
        "🔍 <b>كشف الهوية المشفرة:</b>\n"
        "أرسل الآن رقم الطالب المجهول (مثل <code>154</code>) أو رقم رسالة المنشور في القناة (مثل <code>#342</code>):\n\n"
        "<i>أو أرسل /cancel للإلغاء</i>",
        parse_mode="HTML"
    )
    await callback.answer()


@router.message(AdminState.waiting_for_whois_query)
async def handle_whois_input_state(
    message: Message,
    bot: Bot,
    db: DatabaseManager,
    settings: Settings,
    state: FSMContext
):
    """معالجة رقم البحث لكشف الهوية عبر الحالة"""
    await state.clear()
    if message.text and message.text.strip() == "/cancel":
        await message.answer("❌ تم الإلغاء.")
        return

    from handlers.admin_moderation import execute_whois_lookup
    await execute_whois_lookup(message, bot, db, settings, message.text.strip() if message.text else "")


@router.message(Command("set_admin_password"))
async def handle_set_admin_password_command(
    message: Message,
    db: DatabaseManager,
    settings: Settings
):
    """
    تعيين أو تغيير كلمة مرور فردية لمشرف محدد (حصراً للمسؤول الأساسي)
    الصيغة: /set_admin_password <telegram_id> <password>
    """
    user = message.from_user
    if not user:
        return

    # 1. التحقق من صلاحية المسؤول الأساسي
    if not admin_session_manager.is_primary_admin(user.id, settings):
        await message.answer(
            "⛔ <b>غير مصرح:</b> تعيين كلمات مرور المشرفين متاح حصرياً للمسؤول الأساسي (Primary Admin).",
            parse_mode="HTML"
        )
        return

    # حذف الرسالة إن كانت تحتوي كلمة مرور لحماية الأمان
    text_content = message.text or ""
    parts = text_content.split(maxsplit=2)

    if len(parts) < 3:
        await message.answer(
            "ℹ️ <b>طريقة الاستخدام:</b>\n"
            "<code>/set_admin_password &lt;TELEGRAM_ID&gt; &lt;NEW_PASSWORD&gt;</code>\n\n"
            "<i>(سيتم حذف رسالتك فوراً لحماية كلمة المرور من التسريب في الشات)</i>",
            parse_mode="HTML"
        )
        return

    try:
        await message.delete()
    except Exception:
        pass

    target_id_str = parts[1].strip()
    new_password = parts[2].strip()

    if not target_id_str.lstrip("-").isdigit():
        await message.answer("❌ معرف المشرف يجب أن يكون رقماً صحيحاً (Telegram ID).")
        return

    target_id = int(target_id_str)
    if len(new_password) < 6:
        await message.answer("❌ يجب ألا تقل كلمة المرور عن 6 أحرف أو أرقام لضمان الأمان.")
        return

    target_role = "primary_admin" if (settings.primary_admin_id and target_id == settings.primary_admin_id) else "moderator"
    pw_hash = hash_admin_password(new_password)

    await db.set_admin_credential(
        telegram_id=target_id,
        password_hash=pw_hash,
        role=target_role
    )

    await db.log_audit_action(
        admin_id=user.id,
        action="SET_ADMIN_PASSWORD",
        details=f"تعيين كلمة مرور فردية للمشرف {target_id} برتبة {target_role}"
    )

    await message.answer(
        f"✅ <b>تم تعيين كلمة مرور فردية بنجاح للمشرف:</b> <code>{target_id}</code>\n"
        f"الرتبة: <b>{target_role}</b>\n"
        f"نوع التجزئة: <b>scrypt (N=16384, r=8, p=1)</b>",
        parse_mode="HTML"
    )

