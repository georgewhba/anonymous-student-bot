"""
Content Moderator Facade & Compatibility Layer.
Delegates all content and media moderation directly to the Ultra-Strict Moderation Engine
while preserving 100% backward compatibility for all existing tests and handlers.
"""
from typing import Optional, List, Tuple, Dict, Any
from enum import Enum

from moderation.models import (
    ViolationCategory,
    SeverityLevel,
    ModerationAction,
    ModerationResult
)
from moderation.engine import ModerationEngine, moderation_engine


class ViolationType(str, Enum):
    """توافق كامل مع واجهات التعداد القديمة والجديدة"""
    NONE = "none"
    PROFANITY = "profanity"
    SEXUAL_NSFW = "sexual_nsfw"
    SEXUAL = "sexual"
    EXPLICIT = "explicit"
    INSULT = "insult"
    HARASSMENT = "harassment"
    BULLYING = "bullying"
    THREAT = "threat"
    HATE = "hate"
    SLUR = "slur"
    SELF_HARM = "self_harm"
    VIOLENCE = "violence"
    PII_SELF_DOXX = "pii_self_doxx"
    PHONE_NUMBER = "phone_number"
    EMAIL_ADDRESS = "email_address"
    SOCIAL_LINK = "social_link"
    LINK = "link"
    FLOOD_SPAM = "flood_spam"
    MEDIA_UNSAFE = "media_unsafe"


class ContentModerationEngine:
    """واجهة التوافق لمحرك الفحص المركزي"""

    def __init__(self, custom_profanity: Optional[List[str]] = None):
        self.engine = ModerationEngine(custom_profanity=custom_profanity)

    def inspect_content(self, text: Optional[str]) -> ModerationResult:
        res = self.engine.inspect_content(text)
        # للتوافق القديم إذا كان النوع SEXUAL أو EXPLICIT
        return res

    async def inspect_media(
        self,
        file_path: str,
        media_type: str,
        original_filename: Optional[str] = None,
        caption: Optional[str] = None
    ) -> ModerationResult:
        return await self.engine.inspect_media(
            file_path=file_path,
            media_type=media_type,
            original_filename=original_filename,
            caption=caption
        )


moderator = ContentModerationEngine()
