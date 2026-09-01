"""
Role-Based Access Control Filters for Aiogram.
Enforces Primary Admin vs Moderator permissions.
"""
from typing import Union
from aiogram.filters import BaseFilter
from aiogram.types import Message, CallbackQuery
from config import Settings
from security.auth import admin_session_manager, AdminRole


class IsPrimaryAdmin(BaseFilter):
    """فلتر للتحقق هل المستخدم هو المسؤول الأساسي الوحيد (Primary Admin)"""

    async def __call__(
        self,
        event: Union[Message, CallbackQuery],
        settings: Settings
    ) -> bool:
        user_id = event.from_user.id if event.from_user else 0
        return bool(settings.primary_admin_id and user_id == settings.primary_admin_id)


class IsStaff(BaseFilter):
    """فلتر للتحقق هل المستخدم عضو في فريق الإشراف (مسؤول أساسي أو مشرف)"""

    async def __call__(
        self,
        event: Union[Message, CallbackQuery],
        settings: Settings
    ) -> bool:
        user_id = event.from_user.id if event.from_user else 0
        return user_id in settings.admin_ids


class IsModerator(BaseFilter):
    """فلتر للتحقق هل المستخدم مشرف (Moderator)"""

    async def __call__(
        self,
        event: Union[Message, CallbackQuery],
        settings: Settings
    ) -> bool:
        user_id = event.from_user.id if event.from_user else 0
        return user_id in settings.moderator_ids
