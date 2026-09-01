"""
Moderation Data Models and Types.
Defines violation categories, severity levels, moderation actions, rule structures, and result bundles.
"""
from enum import Enum
from typing import List, Optional, Dict, Any, Set
from dataclasses import dataclass, field


class ViolationCategory(str, Enum):
    NONE = "none"
    PROFANITY = "profanity"          # ألفاظ بذيئة أو سباب عام
    INSULT = "insult"                # إهانات وتنقيص من الشخص
    SEXUAL = "sexual"                # إيحاءات أو محتوى جنسي
    EXPLICIT = "explicit"            # محتوى إباحي صريح
    HARASSMENT = "harassment"        # تحرش لفظي ومضايقة
    BULLYING = "bullying"            # تنمر واعتداء لفظي
    THREAT = "threat"                # تهديدات بالعنف أو الإيذاء
    HATE = "hate"                    # خطاب كراهية وعنصرية
    SLUR = "slur"                    # شتائم عرقية أو دينية
    SELF_HARM = "self_harm"          # إيذاء النفس أو الانتحار
    VIOLENCE = "violence"            # تشجيع العنف أو القتل
    PII_SELF_DOXX = "pii_self_doxx"  # تسريب بيانات شخصية (اسم، هاتف، عمر، عنوان)
    PHONE_NUMBER = "phone_number"    # رقم هاتف
    EMAIL_ADDRESS = "email_address"  # بريد إلكتروني
    SOCIAL_LINK = "social_link"      # حسابات تواصل
    LINK = "link"                    # روابط ودومينات وIP
    MEDIA_UNSAFE = "media_unsafe"    # ملف غير آمن أو تعذر فحصه في نمط strict


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModerationAction(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class ContentType(str, Enum):
    """أنواع المحتوى والوسائط المدعومة في النظام"""
    TEXT = "text"
    PHOTO = "photo"
    DOCUMENT = "document"
    VOICE = "voice"
    AUDIO = "audio"
    VIDEO = "video"
    ANIMATION = "animation"
    STICKER = "sticker"


@dataclass
class ModerationSignal:
    """إشارة رقابية أو أمنية صادرة من أحد المحللات المتخصصة"""
    source: str                          # TEXT, OCR, ASR, VISUAL, DOCUMENT, ARCHIVE, FILE_SECURITY, FILENAME, CAPTION
    category: ViolationCategory
    severity: SeverityLevel
    confidence: float
    is_violation: bool
    reason: str
    detected_item: Optional[str] = None
    is_security: bool = False            # تمييز إشارات الأمان الثنائي (Security) عن إشارات المحتوى (Content)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContentPayload:
    """الحزمة الموحدة لاستقبال وتوصيف أي محتوى مرسل من الطالب قبل الفحص"""
    content_type: ContentType
    raw_source: Optional[str] = None     # النص الخام أو معرف الملف file_id
    file_path: Optional[str] = None      # المسار المحلي المؤقت للملف إن تم تنزيله
    caption: Optional[str] = None        # الكابشن المصاحب للوسائط
    filename: Optional[str] = None       # اسم الملف الأصلي
    mime_type: Optional[str] = None      # نوع MIME
    size_bytes: int = 0                  # حجم الملف بالبايت
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ModerationResult:
    """نتيجة فحص المحتوى الشاملة"""
    is_allowed: bool
    action: ModerationAction
    category: ViolationCategory
    severity: SeverityLevel
    confidence: float
    reason_ar: str
    reasons: List[str] = field(default_factory=list)
    matched_rules: List[str] = field(default_factory=list)
    detected_item: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    signals: List[ModerationSignal] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        """Alias for is_allowed"""
        return self.is_allowed

    @property
    def violation_type(self) -> ViolationCategory:
        """Compatibility property for older code/tests"""
        return self.category

    @property
    def is_blocked(self) -> bool:
        return self.action == ModerationAction.BLOCK

    @property
    def is_review(self) -> bool:
        return self.action == ModerationAction.REVIEW

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.is_allowed,
            "action": self.action.value,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "reason_ar": self.reason_ar,
            "reasons": self.reasons,
            "matched_rules": self.matched_rules,
            "detected_item": self.detected_item,
            "details": self.details,
        }


@dataclass
class NormalizedTextBundle:
    """حزمة تمثيلات النصوص المطهرة لكشف مختلف أشكال التحايل"""
    original: str
    cleaned: str
    normalized_ar: str
    compact_ar: str
    compact_collapsed: str
    letters_only: str
    de_leetspeak: str
    compact_leet: str
    compact_leet_collapsed: str
    de_arabizi: str
    compact_arab: str
    compact_arab_collapsed: str
    de_homoglyphs: str
    phonetic_variants: List[str] = field(default_factory=list)
    compact_variants: List[str] = field(default_factory=list)
    tokens: List[str] = field(default_factory=list)
    char_ngrams: Set[str] = field(default_factory=set)


@dataclass
class ModerationRule:
    """قاعدة رقابية داخل سجل القواعد"""
    rule_id: str
    category: ViolationCategory
    severity: SeverityLevel
    pattern_or_stem: str
    is_regex: bool = False
    is_phrase: bool = False
    is_compact_only: bool = False
    language: str = "ar"
    description: str = ""
