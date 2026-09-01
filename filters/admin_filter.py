"""
Admin filter for Aiogram.
"""
from typing import Union
from aiogram.filters import BaseFilter
from aiogram.types import Message, CallbackQuery
from config import Settings


class IsAdmin(BaseFilter):
    """فلتر للتحقق هل المستخدم أحد المشرفين أو المسؤول الأساسي"""

    async def __call__(
        self,
        event: Union[Message, CallbackQuery],
        settings: Settings
    ) -> bool:
        user_id = event.from_user.id if event.from_user else 0
        return user_id in settings.admin_ids
