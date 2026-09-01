"""
Throttling and Rate Limiting Middleware.
Combines in-memory fast cooldown with SQLite-backed persistent hourly quota tracking.
"""
import time
from typing import Any, Awaitable, Callable, Dict
from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject
from config import Settings
from database.db_manager import DatabaseManager


class ThrottlingMiddleware(BaseMiddleware):
    """
    وسيط برمجي لمكافحة الإغراق والتحكم بمعدل إرسال الرسائل (Rate Limiter)
    يجمع بين مهلة التبريد السريعة (Cooldown) والحصص الساعية المستمرة (Persistent Hourly Quota).
    """

    def __init__(self):
        super().__init__()
        self.user_timestamps: Dict[int, float] = {}

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
        if not settings:
            return await handler(event, data)

        user_id = event.from_user.id

        # المشرفون والمسؤولون مستثنون من قيود المعدل
        if user_id in settings.admin_ids:
            return await handler(event, data)

        # أوامر الاستعلام العامة لا تُخضع لقيود
        if event.text and event.text.startswith(("/start", "/help", "/rules", "/my_id", "/forget_me", "/cancel")):
            return await handler(event, data)

        now = time.time()
        last_time = self.user_timestamps.get(user_id, 0.0)
        cooldown = settings.rate_limit_seconds

        # 1. فحص مهلة التبريد السريعة (Cooldown)
        if now - last_time < cooldown:
            wait_time = int(cooldown - (now - last_time)) + 1
            await event.answer(
                f"⏱️ <b>يرجى التمهل!</b>\n"
                f"أنت ترسل الرسائل بسرعة، انتظر <b>{wait_time}</b> ثوانٍ قبل إرسال المشاركة التالية.",
                parse_mode="HTML"
            )
            return None



        self.user_timestamps[user_id] = now
        return await handler(event, data)
