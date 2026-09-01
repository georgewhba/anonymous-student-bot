"""
Publisher Service Gate Tests.
Verifies that no message or media can reach the channel without passing the mandatory moderation gate.
"""
from unittest.mock import AsyncMock, MagicMock
import pytest
from moderation.publisher import PublisherService
from moderation.models import ModerationAction


@pytest.mark.asyncio
async def test_publisher_gate_blocks_abusive_text_before_api_call():
    mock_bot = MagicMock()
    mock_bot.send_message = AsyncMock()

    publisher = PublisherService()

    success, sent_msg, res = await publisher.publish_post(
        bot=mock_bot,
        channel_id=-100123456,
        media_type="text",
        formatted_html="<b>سؤال</b>\nشرموطة",
        raw_text="شرموطة"
    )

    # 1. فشل النشر
    assert success is False
    assert sent_msg is None
    assert res.is_allowed is False
    assert res.action == ModerationAction.BLOCK

    # 2. التأكد من أن Telegram API لم يتم استدعاؤه مطلقاً
    mock_bot.send_message.assert_not_called()


@pytest.mark.asyncio
async def test_publisher_gate_allows_clean_text_with_protect_content():
    mock_bot = MagicMock()
    fake_sent = MagicMock()
    fake_sent.message_id = 8888
    mock_bot.send_message = AsyncMock(return_value=fake_sent)

    publisher = PublisherService()

    clean_text = "ما هو تعريف الذكاء الاصطناعي وتطبيقاته؟"
    formatted = f"<b>طالب #101</b>\n{clean_text}"

    success, sent_msg, res = await publisher.publish_post(
        bot=mock_bot,
        channel_id=-100123456,
        media_type="text",
        formatted_html=formatted,
        raw_text=clean_text
    )

    assert success is True
    assert sent_msg is not None
    assert res.is_allowed is True
    assert res.action == ModerationAction.ALLOW

    # التأكد من استدعاء send_message مع protect_content=True و reply_markup
    mock_bot.send_message.assert_called_once_with(
        chat_id=-100123456,
        text=formatted,
        parse_mode="HTML",
        reply_to_message_id=None,
        reply_markup=None,
        protect_content=True
    )
