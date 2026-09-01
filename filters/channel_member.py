"""
Channel Membership Gatekeeper.
Checks whether a user is an active member of the private channel
before allowing any anonymous posts or replies.
"""
from typing import Tuple
from aiogram import Bot
from aiogram.enums import ChatMemberStatus
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from utils.logger import logger


async def check_channel_membership(
    bot: Bot,
    channel_id: int,
    user_id: int
) -> Tuple[bool, str]:
    """
    التحقق من عضوية الطالب في القناة الخاصة دون تسجيل بيانات PII في السجلات.
    يرجع: (is_member, status)
    """
    try:
        member = await bot.get_chat_member(chat_id=channel_id, user_id=user_id)
        if member.status in [
            ChatMemberStatus.MEMBER,
            ChatMemberStatus.ADMINISTRATOR,
            ChatMemberStatus.CREATOR,
            # RESTRICTED مستبعد: العضو المقيّد لا يملك صلاحيات كاملة
        ]:
            return True, member.status
        return False, member.status
    except Exception as e:
        logger.warning(f"تعذر التحقق من عضوية القناة: {e}")
        return False, "error"


def get_join_channel_keyboard(channel_invite_link: str) -> InlineKeyboardMarkup:
    """لوحة أزرار تطلب من الطالب الانضمام للقناة الخاصة أولاً"""
    buttons = []
    if channel_invite_link:
        buttons.append([
            InlineKeyboardButton(text="📢 انضم إلى القناة الخاصة أولاً", url=channel_invite_link)
        ])
    buttons.append([
        InlineKeyboardButton(text="🔄 تم الانضمام - تحقق من العضوية", callback_data="check_membership")
    ])
    return InlineKeyboardMarkup(inline_keyboard=buttons)
