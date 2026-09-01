"""
Central Moderation Engine.
Coordinates TextAnalyzer, MediaAnalyzer, RuleRegistry, and ModerationCache
into a unified defense-in-depth moderation gate.
"""
from typing import Optional, List, Any
from moderation.models import (
    ModerationResult,
    ViolationCategory,
    ModerationAction,
    SeverityLevel,
    ContentPayload
)
from moderation.text_analyzer import TextAnalyzer
from moderation.media_analyzer import MediaAnalyzer
from moderation.rules import RuleRegistry
from moderation.cache import ModerationCache, moderation_cache


class ModerationEngine:
    """المحرك المركزي لإدارة وفحص المحتوى الشامل"""

    def __init__(
        self,
        strict_mode: bool = True,
        fail_closed_on_media: bool = True,
        enable_ocr: bool = True,
        enable_asr: bool = False,
        allow_links: bool = False,
        enable_profanity_filter: bool = True,
        block_profanity: bool = True,
        block_sexual: bool = True,
        block_harassment: bool = True,
        block_bullying: bool = True,
        block_threats: bool = True,
        block_hate: bool = True,
        custom_profanity: Optional[List[str]] = None,
        cache: Optional[ModerationCache] = None,
        settings: Optional[Any] = None
    ):
        if settings is not None:
            strict_mode = getattr(settings, "moderation_mode", "strict") == "strict"
            fail_closed_on_media = getattr(settings, "fail_closed_on_media_error", True)
            enable_ocr = getattr(settings, "enable_ocr", True)
            enable_asr = getattr(settings, "enable_asr", False)
            allow_links = getattr(settings, "allow_links_in_submissions", False)
            enable_profanity_filter = getattr(settings, "enable_profanity_filter", True)
            block_profanity = getattr(settings, "block_profanity", True)
            block_sexual = getattr(settings, "block_sexual", True)
            block_harassment = getattr(settings, "block_harassment", True)
            block_bullying = getattr(settings, "block_bullying", True)
            block_threats = getattr(settings, "block_threats", True)
            block_hate = getattr(settings, "block_hate", True)

        self.strict_mode = strict_mode
        self.rules = RuleRegistry()
        if custom_profanity:
            for w in custom_profanity:
                self.rules.arabic_terms.append({
                    "term": w,
                    "cat": ViolationCategory.PROFANITY,
                    "sev": SeverityLevel.HIGH,
                    "stem": True
                })

        self.cache = cache or moderation_cache
        self.text_analyzer = TextAnalyzer(
            rule_registry=self.rules,
            cache=self.cache,
            allow_links=allow_links,
            enable_profanity_filter=enable_profanity_filter,
            block_profanity=block_profanity,
            block_sexual=block_sexual,
            block_harassment=block_harassment,
            block_bullying=block_bullying,
            block_threats=block_threats,
            block_hate=block_hate,
            strict_mode=strict_mode
        )
        self.media_analyzer = MediaAnalyzer(
            text_analyzer=self.text_analyzer,
            fail_closed=fail_closed_on_media,
            enable_ocr=enable_ocr,
            enable_asr=enable_asr,
            allow_links=allow_links,
            enable_profanity_filter=enable_profanity_filter,
            block_profanity=block_profanity,
            block_sexual=block_sexual,
            block_harassment=block_harassment,
            block_bullying=block_bullying,
            block_threats=block_threats,
            block_hate=block_hate
        )

    def inspect_content(self, text: Optional[str]) -> ModerationResult:
        """فحص المحتوى النصي"""
        return self.text_analyzer.analyze(text)

    async def inspect_payload(self, payload: "ContentPayload") -> ModerationResult:
        """فحص الحزمة الموحدة لكافة أنواع المحتوى والوسائط"""
        return await self.media_analyzer.analyze_payload(payload)

    async def inspect_media(
        self,
        file_path: str,
        media_type: str,
        original_filename: Optional[str] = None,
        caption: Optional[str] = None
    ) -> ModerationResult:
        """فحص الوسائط والمستندات والكابشن المصاحب لها"""
        return await self.media_analyzer.analyze_media(
            file_path=file_path,
            media_type=media_type,
            original_filename=original_filename,
            caption=caption
        )


# النسخة العامة الجاهزة للاستخدام في التطبيق
moderation_engine = ModerationEngine()
