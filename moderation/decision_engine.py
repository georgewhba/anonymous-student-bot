"""
Universal Decision Engine.
Aggregates security signals and content signals from all specialized analyzers.
Enforces the strict fail-closed policy, prioritization (BLOCK > REVIEW > ALLOW),
and separates binary security threats from content violations.
"""
from typing import List, Optional, Dict, Any
from moderation.models import (
    ModerationAction,
    ViolationCategory,
    SeverityLevel,
    ModerationResult,
    ModerationSignal
)


class DecisionEngine:
    """
    محرك اتخاذ القرار الرقابي الموحد (Universal Decision Engine)
    يجمع إشارات الفحص من:
    - فحص النصوص (Text)
    - استخراج النصوص بالصور (OCR)
    - التعرف على الصوت (ASR)
    - الفحص البصري (Visual Safety)
    - فحص المستندات (Documents)
    - الفحص العميق للأرشيف (Archive)
    - فحص التواقيع الثنائية والأمان (File Security)
    - فحص اسم الملف (Filename)
    """

    def __init__(
        self,
        strict_mode: bool = True,
        allow_links: bool = False,
        enable_profanity_filter: bool = True,
        block_profanity: bool = True,
        block_sexual: bool = True,
        block_harassment: bool = True,
        block_bullying: bool = True,
        block_threats: bool = True,
        block_hate: bool = True
    ):
        self.strict_mode = strict_mode
        self.allow_links = allow_links
        self.enable_profanity_filter = enable_profanity_filter
        self.block_profanity = block_profanity
        self.block_sexual = block_sexual
        self.block_harassment = block_harassment
        self.block_bullying = block_bullying
        self.block_threats = block_threats
        self.block_hate = block_hate

    def _is_category_blocked(self, category: ViolationCategory) -> bool:
        """التحقق هل الفئة محظورة بناءً على إعدادات الرقابة النشطة"""
        if category == ViolationCategory.LINK and self.allow_links:
            return False
        if not self.enable_profanity_filter and category in (ViolationCategory.PROFANITY, ViolationCategory.INSULT):
            return False
        if category in (ViolationCategory.PROFANITY, ViolationCategory.INSULT) and not self.block_profanity:
            return False
        if category in (ViolationCategory.SEXUAL, ViolationCategory.EXPLICIT) and not self.block_sexual:
            return False
        if category == ViolationCategory.HARASSMENT and not self.block_harassment:
            return False
        if category == ViolationCategory.BULLYING and not self.block_bullying:
            return False
        if category in (ViolationCategory.THREAT, ViolationCategory.VIOLENCE) and not self.block_threats:
            return False
        if category in (ViolationCategory.HATE, ViolationCategory.SLUR) and not self.block_hate:
            return False
        return True

    def evaluate_signals(
        self,
        signals: List[ModerationSignal],
        details: Optional[Dict[str, Any]] = None
    ) -> ModerationResult:
        """
        تقييم كافة الإشارات وتطبيق مصفوفة القرار وقواعد Fail-Closed الصارمة
        """
        if not signals:
            return ModerationResult(
                is_allowed=True,
                action=ModerationAction.ALLOW,
                category=ViolationCategory.NONE,
                severity=SeverityLevel.LOW,
                confidence=1.0,
                reason_ar="",
                reasons=[],
                matched_rules=[],
                signals=[],
                details=details or {}
            )

        # 1. فحص إشارات الأمان الثنائي (Security Signals) أولاً
        # أي تهديد أمني (ملف تنفيذي، قنبلة ضغط، مسار مشبوه، ماكرو، تلف صيغة) -> BLOCK فوري
        security_violations = [s for s in signals if s.is_violation and s.is_security]
        if security_violations:
            top_sec = max(security_violations, key=lambda s: (self._sev_score(s.severity), s.confidence))
            all_reasons = [f"[{s.source}] {s.reason}" for s in security_violations]
            return ModerationResult(
                is_allowed=False,
                action=ModerationAction.BLOCK,
                category=top_sec.category,
                severity=top_sec.severity,
                confidence=top_sec.confidence,
                reason_ar=self._format_security_reason_ar(top_sec),
                reasons=all_reasons,
                matched_rules=[f"RULE_SECURITY_{s.source}" for s in security_violations],
                detected_item=top_sec.detected_item,
                signals=signals,
                details=details or {}
            )

        # 2. فحص إشارات المحتوى غير اللائق (Content Violations)
        content_violations = [
            s for s in signals
            if s.is_violation and not s.is_security and self._is_category_blocked(s.category)
        ]
        if content_violations:
            top_content = max(content_violations, key=lambda s: (self._sev_score(s.severity), s.confidence))
            all_reasons = [f"[{s.source}] {s.reason}" for s in content_violations]

            # تحديد الإجراء بناءً على مستوى الخطورة والنمط الصارم
            if top_content.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) or self.strict_mode:
                action = ModerationAction.BLOCK
            elif top_content.severity == SeverityLevel.MEDIUM:
                action = ModerationAction.REVIEW if not self.strict_mode else ModerationAction.BLOCK
            else:
                action = ModerationAction.REVIEW

            return ModerationResult(
                is_allowed=False if action == ModerationAction.BLOCK else True,
                action=action,
                category=top_content.category,
                severity=top_content.severity,
                confidence=top_content.confidence,
                reason_ar=self._format_content_reason_ar(top_content),
                reasons=all_reasons,
                matched_rules=[f"RULE_{s.source}_{s.category.value.upper()}" for s in content_violations],
                detected_item=top_content.detected_item,
                signals=signals,
                details=details or {}
            )

        # 3. محتوى آمن تماماً
        return ModerationResult(
            is_allowed=True,
            action=ModerationAction.ALLOW,
            category=ViolationCategory.NONE,
            severity=SeverityLevel.LOW,
            confidence=1.0,
            reason_ar="",
            reasons=[],
            matched_rules=[],
            signals=signals,
            details=details or {}
        )

    def _sev_score(self, sev: SeverityLevel) -> int:
        scores = {
            SeverityLevel.CRITICAL: 4,
            SeverityLevel.HIGH: 3,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 1
        }
        return scores.get(sev, 0)

    def _format_security_reason_ar(self, sig: ModerationSignal) -> str:
        """صياغة سبب الرفض الأمني باللغة العربية"""
        if "zip bomb" in sig.reason.lower() or "expansion" in sig.reason.lower():
            return "⚠️ تم رفض الأرشيف لحمايتنا من هجمات قنابل إلغاء الضغط."
        if "executable" in sig.reason.lower() or "binary" in sig.reason.lower():
            return "🚫 تم رفض الملف لاحتوائه على ملفات برمجية أو تنفيذية محظورة أمنياً."
        if "path traversal" in sig.reason.lower():
            return "⚠️ تم رفض الملف لاحتوائه على مسارات غير آمنة."
        if "macro" in sig.reason.lower():
            return "🚫 تم رفض المستند لاحتوائه على ماكرو برمجي غير مصرح به."
        if "dimension" in sig.reason.lower() or "decompression" in sig.reason.lower():
            return "⚠️ أبعاد الملف/الصورة تتجاوز الحد الأقصى الآمن المسموح به."
        if "unsupported" in sig.reason.lower():
            return "⚠️ نوع الملف غير مدعوم للفحص الأمني في القناة التعليمية."
        return "❌ تم رفض الملف لعدم اجتيازه متطلبات الفحص الأمني."

    def _format_content_reason_ar(self, sig: ModerationSignal) -> str:
        """صياغة سبب رفض المحتوى المخالف باللغة العربية"""
        cat = sig.category
        if cat in (ViolationCategory.PROFANITY, ViolationCategory.INSULT):
            return "🚫 تم رفض المحتوى لاحتوائه على شتائم أو ألفاظ مسيئة للآخرين."
        elif cat in (ViolationCategory.EXPLICIT, ViolationCategory.SEXUAL):
            return "🚫 تم رفض المحتوى لاحتوائه على مواد أو إيحاءات غير لائقة."
        elif cat in (ViolationCategory.HARASSMENT, ViolationCategory.BULLYING):
            return "🚫 تم رفض المحتوى لمخالفته معايير الاحترام ومكافحة التنمر والمضايقة."
        elif cat == ViolationCategory.THREAT:
            return "🚫 تم رفض المحتوى لاحتوائه على تهديدات بالعنف أو الإيذاء."
        elif cat in (ViolationCategory.HATE, ViolationCategory.SLUR):
            return "🚫 تم رفض المحتوى لاحتوائه على خطاب كراهية أو تمييز مسيء."
        elif cat == ViolationCategory.SELF_HARM:
            return "🚫 تم حظر الرسالة لاحتوائها على عبارات إيذاء النفس أو الانتحار."
        elif cat in (ViolationCategory.PII_SELF_DOXX, ViolationCategory.PHONE_NUMBER, ViolationCategory.EMAIL_ADDRESS):
            return "🔒 تم رفض المحتوى لحماية خصوصيتك (تسريب أرقام هواتف أو بيانات شخصية)."
        elif cat == ViolationCategory.LINK:
            return "🚫 تم رفض المحتوى لاحتوائه على روابط أو معرفات خارجية غير مسموح بنشرها."
        elif cat == ViolationCategory.MEDIA_UNSAFE:
            return "❌ تعذر التحقق من أمان وسلامة المحتوى المرفوع."
        return "🚫 تم رفض المحتوى لمخالفته شروط النشر وسياسة المحتوى."
