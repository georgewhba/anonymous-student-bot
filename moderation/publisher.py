"""
Mandatory Channel Publisher Gate.
Enforces that no message, media, or reply reaches the private Telegram channel
without strictly passing through the Moderation Gate with protect_content=True.
"""
from typing import Optional, Tuple, Any
from aiogram import Bot
from aiogram.types import Message, FSInputFile, InlineKeyboardMarkup

from moderation.models import ModerationResult, ModerationAction, ViolationCategory, SeverityLevel
from moderation.engine import ModerationEngine, moderation_engine
from utils.logger import logger


class PublisherService:
    """بوابة النشر الإلزامية في القناة الخاصة (Mandatory Publishing Gate)"""

    def __init__(self, engine: Optional[ModerationEngine] = None):
        self.engine = engine or moderation_engine

    async def publish_post(
        self,
        bot: Bot,
        channel_id: int,
        media_type: str,
        formatted_html: str,
        raw_text: str,
        media_path: Optional[str] = None,
        original_filename: Optional[str] = None,
        reply_to_message_id: Optional[int] = None,
        reply_markup: Optional[Any] = None
    ) -> Tuple[bool, Optional[Message], ModerationResult]:
        """
        فحص المحتوى والوسائط أمنياً ورقابياً قبل إرسالها فعلياً إلى القناة
        مع دعم نشر أزرار الرد الذكية ذرياً في نفس الطلب
        يرجع: (success, sent_message, moderation_result)
        """
        # 1. الفحص الرقابي للنص والكابشن
        text_res = self.engine.inspect_content(raw_text)
        if not text_res.is_allowed:
            return False, None, text_res

        # 2. الفحص الرقابي للوسائط إن وجدت
        if media_path:
            media_res = await self.engine.inspect_media(
                file_path=media_path,
                media_type=media_type,
                original_filename=original_filename,
                caption=raw_text
            )
            if not media_res.is_allowed:
                return False, None, media_res

        # 3. النشر الفعلي في القناة مع تفعيل protect_content=True والأزرار الذرية
        from aiogram.exceptions import TelegramBadRequest

        async def _do_send(reply_to: Optional[int]) -> Optional[Message]:
            if media_type == "text":
                return await bot.send_message(
                    chat_id=channel_id,
                    text=formatted_html,
                    parse_mode="HTML",
                    reply_to_message_id=reply_to,
                    reply_markup=reply_markup,
                    protect_content=True
                )
            elif media_path:
                input_file = FSInputFile(media_path, filename=original_filename)
                if media_type == "photo":
                    return await bot.send_photo(
                        chat_id=channel_id,
                        photo=input_file,
                        caption=formatted_html,
                        parse_mode="HTML",
                        reply_to_message_id=reply_to,
                        reply_markup=reply_markup,
                        protect_content=True
                    )
                elif media_type == "voice":
                    return await bot.send_voice(
                        chat_id=channel_id,
                        voice=input_file,
                        caption=formatted_html,
                        parse_mode="HTML",
                        reply_to_message_id=reply_to,
                        reply_markup=reply_markup,
                        protect_content=True
                    )
                elif media_type == "video_note":
                    return await bot.send_video_note(
                        chat_id=channel_id,
                        video_note=input_file,
                        reply_to_message_id=reply_to,
                        reply_markup=reply_markup,
                        protect_content=True
                    )
                elif media_type == "sticker":
                    return await bot.send_sticker(
                        chat_id=channel_id,
                        sticker=input_file,
                        reply_to_message_id=reply_to,
                        reply_markup=reply_markup,
                        protect_content=True
                    )
                elif media_type == "document":
                    return await bot.send_document(
                        chat_id=channel_id,
                        document=input_file,
                        caption=formatted_html,
                        parse_mode="HTML",
                        reply_to_message_id=reply_to,
                        reply_markup=reply_markup,
                        protect_content=True
                    )
                elif media_type == "video":
                    return await bot.send_video(
                        chat_id=channel_id,
                        video=input_file,
                        caption=formatted_html,
                        parse_mode="HTML",
                        reply_to_message_id=reply_to,
                        reply_markup=reply_markup,
                        protect_content=True
                    )
                elif media_type == "audio":
                    return await bot.send_audio(
                        chat_id=channel_id,
                        audio=input_file,
                        caption=formatted_html,
                        parse_mode="HTML",
                        reply_to_message_id=reply_to,
                        reply_markup=reply_markup,
                        protect_content=True
                    )
                elif media_type == "animation":
                    return await bot.send_animation(
                        chat_id=channel_id,
                        animation=input_file,
                        caption=formatted_html,
                        parse_mode="HTML",
                        reply_to_message_id=reply_to,
                        reply_markup=reply_markup,
                        protect_content=True
                    )
            return None

        try:
            try:
                sent_msg = await _do_send(reply_to_message_id)
            except TelegramBadRequest as ex:
                if reply_to_message_id and ("reply" in str(ex).lower() or "not found" in str(ex).lower()):
                    logger.warning(f"الرسالة المردود عليها محذوفة، سيتم إرسالها كمنشور عادي. ({ex})")
                    sent_msg = await _do_send(None)
                else:
                    raise ex

            if not sent_msg:
                return False, None, ModerationResult(
                    is_allowed=False,
                    action=ModerationAction.BLOCK,
                    category=ViolationCategory.MEDIA_UNSAFE,
                    severity=SeverityLevel.HIGH,
                    confidence=1.0,
                    reason_ar="❌ تعذر نشر المحتوى في القناة."
                )

            return True, sent_msg, text_res

        except Exception as e:
            logger.error(f"خطأ أثناء نشر الرسالة في القناة: {e}")
            return False, None, ModerationResult(
                is_allowed=False,
                action=ModerationAction.BLOCK,
                category=ViolationCategory.MEDIA_UNSAFE,
                severity=SeverityLevel.HIGH,
                confidence=1.0,
                reason_ar="❌ تعذر النشر في القناة. يرجى التحقق من صلاحيات البوت وحجم الوسائط."
            )

    async def edit_channel_message_reply_markup(
        self,
        bot: Bot,
        channel_id: int,
        message_id: int,
        reply_markup: Optional[InlineKeyboardMarkup] = None
    ) -> bool:
        """
        بوابة تعديل أزرار رسالة في القناة الخاصة بشكل آمن ومعالجة الاستثناءات
        """
        try:
            await bot.edit_message_reply_markup(
                chat_id=channel_id,
                message_id=message_id,
                reply_markup=reply_markup
            )
            return True
        except Exception as e:
            logger.warning(f"فشل تعديل أزرار الرسالة #{message_id} في القناة #{channel_id}: {e}")
            return False

    async def delete_channel_message(
        self,
        bot: Bot,
        channel_id: int,
        message_id: int
    ) -> bool:
        """
        بوابة حذف رسالة من القناة الخاصة مع معالجة الأخطاء والتسجيل الأمني
        """
        try:
            return await bot.delete_message(chat_id=channel_id, message_id=message_id)
        except Exception as e:
            logger.error(f"فشل حذف الرسالة #{message_id} من القناة #{channel_id}: {e}")
            return False


# البوابة العامة للنشر
publisher_service = PublisherService()

