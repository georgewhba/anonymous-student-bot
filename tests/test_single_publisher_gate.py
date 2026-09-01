"""
Single Publisher Gate Test Suite.
Verifies that all channel publications strictly pass through PublisherService
with content protection and atomic keyboard attachments.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from moderation.publisher import PublisherService
from moderation.models import ModerationResult, ModerationAction, ViolationCategory, SeverityLevel
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton


@pytest.fixture
def mock_engine_allow():
    engine = MagicMock()
    engine.inspect_content.return_value = ModerationResult(
        is_allowed=True,
        action=ModerationAction.ALLOW,
        category=ViolationCategory.NONE,
        severity=SeverityLevel.LOW,
        confidence=1.0,
        reason_ar=""
    )
    async def inspect_media_mock(*args, **kwargs):
        return ModerationResult(
            is_allowed=True,
            action=ModerationAction.ALLOW,
            category=ViolationCategory.NONE,
            severity=SeverityLevel.LOW,
            confidence=1.0,
            reason_ar=""
        )
    engine.inspect_media = AsyncMock(side_effect=inspect_media_mock)
    return engine


@pytest.fixture
def mock_engine_block():
    engine = MagicMock()
    engine.inspect_content.return_value = ModerationResult(
        is_allowed=False,
        action=ModerationAction.BLOCK,
        category=ViolationCategory.PROFANITY,
        severity=SeverityLevel.HIGH,
        confidence=1.0,
        reason_ar="🚫 محتوى محظور"
    )
    return engine


@pytest.mark.asyncio
async def test_publisher_gate_blocks_violating_content(mock_engine_block):
    publisher = PublisherService(engine=mock_engine_block)
    mock_bot = MagicMock()
    mock_bot.send_message = AsyncMock()

    success, msg, res = await publisher.publish_post(
        bot=mock_bot,
        channel_id=-100123456789,
        media_type="text",
        formatted_html="<b>محتوى مخالف</b>",
        raw_text="محتوى مخالف"
    )

    assert success is False
    assert msg is None
    assert res.is_allowed is False
    assert res.category == ViolationCategory.PROFANITY
    mock_bot.send_message.assert_not_called()


@pytest.mark.asyncio
async def test_publisher_gate_enforces_protect_content_and_atomic_markup(mock_engine_allow):
    publisher = PublisherService(engine=mock_engine_allow)
    mock_bot = MagicMock()
    mock_msg = MagicMock()
    mock_msg.message_id = 999
    mock_bot.send_message = AsyncMock(return_value=mock_msg)

    keyboard = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="💬 رد مجهول", url="https://t.me/test_bot?start=reply_999")
    ]])

    success, msg, res = await publisher.publish_post(
        bot=mock_bot,
        channel_id=-100123456789,
        media_type="text",
        formatted_html="<b>سؤال مشروع</b>",
        raw_text="سؤال مشروع",
        reply_markup=keyboard
    )

    assert success is True
    assert msg.message_id == 999
    assert res.is_allowed is True

    # التحقق من أن protect_content=True و reply_markup مررا في نفس الطلب
    mock_bot.send_message.assert_called_once_with(
        chat_id=-100123456789,
        text="<b>سؤال مشروع</b>",
        parse_mode="HTML",
        reply_to_message_id=None,
        reply_markup=keyboard,
        protect_content=True
    )


@pytest.mark.asyncio
async def test_publisher_gate_delete_channel_message():
    publisher = PublisherService()
    mock_bot = MagicMock()
    mock_bot.delete_message = AsyncMock(return_value=True)

    result = await publisher.delete_channel_message(
        bot=mock_bot,
        channel_id=-100123456789,
        message_id=555
    )

    assert result is True
    mock_bot.delete_message.assert_called_once_with(chat_id=-100123456789, message_id=555)
