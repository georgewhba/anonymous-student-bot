"""
Moderation Check Middleware.
Validates student ban/mute status and system submission switch.
"""
from typing import Any, Awaitable, Callable, Dict
from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject
from database.db_manager import DatabaseManager
from config import Settings


class ModerationCheckMiddleware(BaseMiddleware):
    """
    وسيط للتحقق من حالة الطالب (حظر / كتم) وحالة استقبال الأسئلة بالنظام
    دون تسجيل أي بيانات PII في السجلات.
    """

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any]
    ) -> Any:
        if not isinstance(event, Message) or not event.from_user:
            return await handler(event, data)

        settings: Settings = data.get("settings")
        db: DatabaseManager = data.get("db")

        if not settings or not db:
            return await handler(event, data)

        user_id = event.from_user.id

        # المشرفون والمسؤول الأساسي يتجاوزون هذه القيود
        if user_id in settings.admin_ids:
            return await handler(event, data)

        # السماح بالأوامر التعريفية دائماً
        if event.text and event.text.startswith(("/start", "/help", "/rules", "/my_id", "/forget_me", "/cancel")):
            return await handler(event, data)

        student = await db.get_student_by_telegram_id(user_id)

        if student:
            # 1. التحقق من الحظر
            if student.is_banned:
                reason = f"\nالسبب: <i>{student.ban_reason}</i>" if student.ban_reason else ""
                await event.answer(
                    f"🚫 <b>عذراً، حسابك محظور من النشر في القناة.</b>{reason}",
                    parse_mode="HTML"
                )
                return None

            # 2. التحقق من الكتم المؤقت
            is_muted, rem_mins = db.is_student_muted(student)
            if is_muted:
                await event.answer(
                    f"⏳ <b>أنت موقوف مؤقتاً عن النشر والمشاركة.</b>\n"
                    f"الوقت المتبقي لفك الكتم: <b>{rem_mins}</b> دقيقة.",
                    parse_mode="HTML"
                )
                return None

        # 3. التحقق من تفعيل استقبال الأسئلة
        sub_enabled = await db.get_system_setting("submissions_enabled", "true")
        if sub_enabled != "true":
            await event.answer(
                "⏸️ <b>استقبال الأسئلة والمشاركات متوقف حالياً.</b>\n"
                "تم إيقاف النشر مؤقتاً من قِبل إدارة القناة، يرجى المحاولة لاحقاً.",
                parse_mode="HTML"
            )
            return None

        return await handler(event, data)
