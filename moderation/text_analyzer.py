"""
Multi-Stage NLP Text Analyzer.
Orchestrates normalization, exact, evasive, stem, phrase, and bounded fuzzy matching
with strict false-positive controls, academic whitelist, and zero-PII caching.
"""
import re
from typing import Optional, List, Dict, Tuple
from moderation.models import (
    ViolationCategory,
    SeverityLevel,
    ModerationAction,
    ModerationResult,
    NormalizedTextBundle
)
from moderation.normalizer import TextNormalizer, COLLAPSE_SINGLE_REGEX
from moderation.fuzzy import is_fuzzy_match
from moderation.rules import RuleRegistry
from moderation.cache import moderation_cache, ModerationCache

# الحد الأقصى لطول النص المدخل لمنع هجمات الاستنزاف (DoS Protection)
MAX_INPUT_TEXT_LENGTH = 10000


class TextAnalyzer:
    """محلل النصوص الذكي متعدد الطبقات"""

    def __init__(
        self,
        rule_registry: Optional[RuleRegistry] = None,
        cache: Optional[ModerationCache] = None,
        allow_links: bool = False,
        enable_profanity_filter: bool = True,
        block_profanity: bool = True,
        block_sexual: bool = True,
        block_harassment: bool = True,
        block_bullying: bool = True,
        block_threats: bool = True,
        block_hate: bool = True,
        strict_mode: bool = True
    ):
        self.rules = rule_registry or RuleRegistry()
        self.cache = cache or moderation_cache
        self.allow_links = allow_links
        self.enable_profanity_filter = enable_profanity_filter
        self.block_profanity = block_profanity
        self.block_sexual = block_sexual
        self.block_harassment = block_harassment
        self.block_bullying = block_bullying
        self.block_threats = block_threats
        self.block_hate = block_hate
        self.strict_mode = strict_mode

    def _is_category_blocked(self, category: ViolationCategory) -> bool:
        """التحقق هل الفئة محظورة بناءً على إعدادات الرقابة النشطة"""
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

    def analyze(self, raw_text: Optional[str]) -> ModerationResult:
        """
        تحليل النص عبر خط الأنابيب الكامل (Multi-Layer Pipeline)
        وإرجاع كائن ModerationResult مفصل
        """
        if not raw_text or not raw_text.strip():
            return ModerationResult(
                is_allowed=True,
                action=ModerationAction.ALLOW,
                category=ViolationCategory.NONE,
                severity=SeverityLevel.LOW,
                confidence=1.0,
                reason_ar=""
            )

        # فحص الحجم لمنع هجمات الاستنزاف
        bounded_text = raw_text[:MAX_INPUT_TEXT_LENGTH]

        # 0. التحقق من الذاكرة المؤقتة (LRU Cache)
        cached_result = self.cache.get(bounded_text)
        if cached_result is not None:
            return cached_result

        # 1. بناء حزمة التمثيلات المطهرة
        bundle: NormalizedTextBundle = TextNormalizer.process(bounded_text)

        # -------------------------------------------------------------
        # الطبقة 0: الفحص السريع للقواعد القديمة (Fast Legacy Rules Pre-check)
        # -------------------------------------------------------------
        if self._is_category_blocked(ViolationCategory.PROFANITY):
            legacy_profane, legacy_word = self._fast_legacy_check(bounded_text)
            if legacy_profane and legacy_word:
                # التحقق هل الكلمة استثناء أكاديمي مصرح به
                tokens_raw = [t.lower() for t in re.split(r"[\s\W_]+", bounded_text) if t]
                if not self._is_whitelisted(tokens_raw, legacy_word.lower()):
                    res = ModerationResult(
                        is_allowed=False,
                        action=ModerationAction.BLOCK,
                        category=ViolationCategory.PROFANITY,
                        severity=SeverityLevel.HIGH,
                        confidence=1.0,
                        reason_ar=self._get_arabic_reason_for_category(ViolationCategory.PROFANITY),
                        reasons=[f"Matched fast legacy rule: {legacy_word}"],
                        matched_rules=["RULE_LEGACY_FAST_PRECHECK"],
                        detected_item=legacy_word
                    )
                    self.cache.set(bounded_text, res)
                    return res

        # 1. بناء حزمة التمثيلات المطهرة (Unicode / Arabic / English / Arabizi / Leet / Homoglyph)
        bundle: NormalizedTextBundle = TextNormalizer.process(bounded_text)

        # -------------------------------------------------------------
        # الطبقة 1: فحص البيانات الشخصية الصريحة أولاً (PII / Emails / Phones)
        # -------------------------------------------------------------
        pii_match = self.rules.match_pii(bundle.original) or self.rules.match_pii(bundle.normalized_ar)
        if pii_match:
            cat, sev, item, reason_msg = pii_match
            res = ModerationResult(
                is_allowed=False,
                action=ModerationAction.BLOCK,
                category=cat,
                severity=sev,
                confidence=0.95,
                reason_ar=f"🔒 <b>حفاظاً على خصوصيتك وأمانك:</b> {reason_msg}",
                reasons=["Detected self-doxxing PII"],
                matched_rules=["RULE_PII_LEAK"],
                detected_item=item
            )
            self.cache.set(bounded_text, res)
            return res

        # -------------------------------------------------------------
        # الطبقة 2: فحص الروابط والدومينات (أولوية مطلقة لحماية القناة)
        # -------------------------------------------------------------
        if not self.allow_links:
            link_match = self.rules.match_links(bundle.original)
            if link_match:
                cat, sev, item = link_match
                res = ModerationResult(
                    is_allowed=False,
                    action=ModerationAction.BLOCK,
                    category=cat,
                    severity=sev,
                    confidence=1.0,
                    reason_ar="🚫 <b>يُمنع نهائياً إرسال أي روابط أو عناوين مواقع أو معرفات تواصل خارجية.</b>",
                    reasons=["Detected external link or URL handle"],
                    matched_rules=["RULE_ALL_LINKS"],
                    detected_item=item
                )
                self.cache.set(bounded_text, res)
                return res

        # -------------------------------------------------------------
        # الطبقة 3: فحص الأنماط الهيكلية والمشوهة (Evasive Regex Patterns)
        # -------------------------------------------------------------
        for variant in (bundle.original, bundle.normalized_ar, bundle.de_leetspeak, bundle.de_arabizi, bundle.compact_ar, bundle.compact_collapsed, bundle.compact_leet, bundle.compact_arab):
            evasive_match = self.rules.match_evasive_patterns(variant)
            if evasive_match:
                cat, sev, item = evasive_match
                if self._is_category_blocked(cat):
                    res = ModerationResult(
                        is_allowed=False,
                        action=ModerationAction.BLOCK,
                        category=cat,
                        severity=sev,
                        confidence=0.98,
                        reason_ar=self._get_arabic_reason_for_category(cat),
                        reasons=["Matched evasive profanity pattern"],
                        matched_rules=["RULE_EVASIVE_REGEX"],
                        detected_item=item
                    )
                    self.cache.set(bounded_text, res)
                    return res

        # -------------------------------------------------------------
        # الطبقة 4: فحص إقحام الأحرف والمحارف الفاصلة (Character Insertion Detection)
        # -------------------------------------------------------------
        for variant in (bundle.original, bundle.normalized_ar, bundle.de_leetspeak, bundle.de_arabizi, bundle.de_homoglyphs):
            insertion_match = self.rules.match_character_insertion(variant)
            if insertion_match:
                cat, sev, matched_text, stem_term = insertion_match
                if self._is_category_blocked(cat) and not self._is_whitelisted(bundle.tokens, stem_term):
                    res = ModerationResult(
                        is_allowed=False,
                        action=ModerationAction.BLOCK,
                        category=cat,
                        severity=sev,
                        confidence=0.98,
                        reason_ar=self._get_arabic_reason_for_category(cat),
                        reasons=[f"Matched character insertion evasion for stem '{stem_term}'"],
                        matched_rules=["RULE_CHARACTER_INSERTION"],
                        detected_item=matched_text
                    )
                    self.cache.set(bounded_text, res)
                    return res

        # -------------------------------------------------------------
        # الطبقة 5: فحص العبارات المركبة المسيئة (Abusive Multi-Word Phrases)
        # -------------------------------------------------------------
        for variant in (bundle.original, bundle.normalized_ar, bundle.de_leetspeak, bundle.de_arabizi, bundle.compact_ar):
            phrase_match = self.rules.match_phrases(variant)
            if phrase_match:
                cat, sev, item = phrase_match
                if self._is_category_blocked(cat):
                    res = ModerationResult(
                        is_allowed=False,
                        action=ModerationAction.BLOCK,
                        category=cat,
                        severity=sev,
                        confidence=0.99,
                        reason_ar=self._get_arabic_reason_for_category(cat),
                        reasons=["Matched abusive multi-word phrase"],
                        matched_rules=["RULE_ABUSIVE_PHRASE"],
                        detected_item=item
                    )
                    self.cache.set(bounded_text, res)
                    return res

        # -------------------------------------------------------------
        # الطبقة 6: فحص القواميس المصنفة (Arabic / English / Arabizi Dictionaries)
        # -------------------------------------------------------------
        # أ) القاموس العربي
        for entry in self.rules.arabic_terms:
            if not self._is_category_blocked(entry["cat"]):
                continue
            term = entry["term"]
            norm_term = TextNormalizer.normalize_arabic(term)
            norm_term_collapsed = COLLAPSE_SINGLE_REGEX.sub(r"\1", norm_term)
            is_stem = entry.get("stem", False)

            if is_stem:
                # فحص بالتمثيل المطبع والتمثيلات المضغوطة
                matched = False
                if norm_term in bundle.normalized_ar or norm_term_collapsed in bundle.normalized_ar:
                    matched = True
                else:
                    for cv in bundle.compact_variants:
                        if (len(norm_term) >= 3 and norm_term in cv) or (len(norm_term_collapsed) >= 3 and norm_term_collapsed in cv):
                            matched = True
                            break

                if matched and not self._is_whitelisted(bundle.tokens, norm_term):
                    res = ModerationResult(
                        is_allowed=False,
                        action=ModerationAction.BLOCK,
                        category=entry["cat"],
                        severity=entry["sev"],
                        confidence=0.95,
                        reason_ar=self._get_arabic_reason_for_category(entry["cat"]),
                        reasons=[f"Matched Arabic dictionary stem: {term}"],
                        matched_rules=["RULE_AR_DICT_STEM"],
                        detected_item=term
                    )
                    self.cache.set(bounded_text, res)
                    return res
            else:
                # فحص بحدود الكلمة (Word Boundary) لمنع الإيجابيات الكاذبة
                if re.search(rf"(?:\b|^|\s){re.escape(norm_term)}(?:\b|$|\s)", bundle.normalized_ar):
                    if not self._is_whitelisted(bundle.tokens, norm_term):
                        res = ModerationResult(
                            is_allowed=False,
                            action=ModerationAction.BLOCK,
                            category=entry["cat"],
                            severity=entry["sev"],
                            confidence=0.95,
                            reason_ar=self._get_arabic_reason_for_category(entry["cat"]),
                            reasons=[f"Matched Arabic exact term: {term}"],
                            matched_rules=["RULE_AR_DICT_EXACT"],
                            detected_item=term
                        )
                        self.cache.set(bounded_text, res)
                        return res

        # ب) القاموس الإنجليزي والفرنكو
        for entry in self.rules.english_terms + self.rules.arabizi_terms:
            if not self._is_category_blocked(entry["cat"]):
                continue
            term = entry["term"].lower()
            term_collapsed = COLLAPSE_SINGLE_REGEX.sub(r"\1", term)
            is_stem = entry.get("stem", False)

            if is_stem:
                matched = False
                for variant_text in (bundle.de_leetspeak, bundle.de_arabizi, bundle.normalized_ar):
                    if re.search(rf"\b{re.escape(term)}", variant_text, re.IGNORECASE) or re.search(rf"\b{re.escape(term_collapsed)}", variant_text, re.IGNORECASE):
                        matched = True
                        break

                if not matched:
                    for cv in bundle.compact_variants:
                        if (len(term) >= 3 and term in cv) or (len(term_collapsed) >= 3 and term_collapsed in cv):
                            matched = True
                            break

                if matched and not self._is_whitelisted(bundle.tokens, term):
                    res = ModerationResult(
                        is_allowed=False,
                        action=ModerationAction.BLOCK,
                        category=entry["cat"],
                        severity=entry["sev"],
                        confidence=0.95,
                        reason_ar=self._get_arabic_reason_for_category(entry["cat"]),
                        reasons=[f"Matched English/Arabizi stem: {term}"],
                        matched_rules=["RULE_EN_DICT_STEM"],
                        detected_item=term
                    )
                    self.cache.set(bounded_text, res)
                    return res
            else:
                for variant_text in (bundle.de_leetspeak, bundle.de_arabizi, bundle.normalized_ar):
                    if re.search(rf"\b{re.escape(term)}\b", variant_text, re.IGNORECASE):
                        if not self._is_whitelisted(bundle.tokens, term):
                            res = ModerationResult(
                                is_allowed=False,
                                action=ModerationAction.BLOCK,
                                category=entry["cat"],
                                severity=entry["sev"],
                                confidence=0.95,
                                reason_ar=self._get_arabic_reason_for_category(entry["cat"]),
                                reasons=[f"Matched English/Arabizi exact: {term}"],
                                matched_rules=["RULE_EN_DICT_EXACT"],
                                detected_item=term
                            )
                            self.cache.set(bounded_text, res)
                            return res

        # -------------------------------------------------------------
        # الطبقة 7: الفحص الضبابي المقيد (Bounded Fuzzy Matching)
        # -------------------------------------------------------------
        for token in bundle.tokens:
            token_lower = token.lower()
            if len(token_lower) < 4:
                continue

            # تجاوز الكلمات الأكاديمية المصرحة
            if token_lower in self.rules.whitelist:
                continue

            for entry in self.rules.arabic_terms + self.rules.english_terms:
                if not self._is_category_blocked(entry["cat"]):
                    continue
                target_term = entry.get("term", "").lower()
                if len(target_term) < 4:
                    continue

                matched, sim = is_fuzzy_match(token_lower, target_term)
                if matched and sim >= 0.75:
                    res = ModerationResult(
                        is_allowed=False,
                        action=ModerationAction.BLOCK,
                        category=entry["cat"],
                        severity=entry["sev"],
                        confidence=round(sim, 2),
                        reason_ar=self._get_arabic_reason_for_category(entry["cat"]),
                        reasons=[f"Fuzzy match token '{token}' with '{target_term}' (sim={sim:.2f})"],
                        matched_rules=["RULE_BOUNDED_FUZZY"],
                        detected_item=target_term
                    )
                    self.cache.set(bounded_text, res)
                    return res

        # النص نظيف ومصرح به
        clean_res = ModerationResult(
            is_allowed=True,
            action=ModerationAction.ALLOW,
            category=ViolationCategory.NONE,
            severity=SeverityLevel.LOW,
            confidence=1.0,
            reason_ar=""
        )
        self.cache.set(bounded_text, clean_res)
        return clean_res

    def _fast_legacy_check(self, text: str) -> Tuple[bool, Optional[str]]:
        """الفحص السريع المتوافق مع محرك الكلمات القديم"""
        norm = TextNormalizer.normalize_arabic(text)
        cleaned_chars = re.sub(r"[^\w\s]", "", norm)
        compact = cleaned_chars.replace(" ", "")

        legacy_words = [
            "قحبة", "شرموطة", "شرموط", "منيك", "منيوك", "كس", "طيز", "عرص", "ديوث",
            "خول", "سافل", "حقير", "زب", "لعنة", "يلعن", "كلب", "ابن الكلب", "ابن الحرام",
            "عاهر", "عاهرة", "قذر", "تفو", "لوطي", "شاذ", "ممحون", "سكس", "بورن",
            "fuck", "shit", "bitch", "asshole", "dick", "pussy", "cunt", "bastard", "dck", "ass"
        ]

        for w in legacy_words:
            nw = TextNormalizer.normalize_arabic(w).lower()
            if re.search(rf"(?:\b|^|\s){re.escape(nw)}(?:\b|$|\s)", norm.lower()):
                return True, w
            if w in ("fuck", "shit", "bitch", "شرموطة", "قحبة", "كسم", "منيوك") and len(nw) >= 4 and nw in compact.lower():
                return True, w

        return False, None

    def _is_whitelisted(self, tokens: List[str], prohibited_term: str) -> bool:
        """
        التحقق هل الكلمة المكتشفة جزء من كلمة مصرحة في القائمة البيضاء الأكاديمية.
        القاعدة: القائمة البيضاء لا تتجاوز الكلمات البذيئة الصريحة بحد ذاتها (No Moderation Bypass).
        """
        prohibited_clean = prohibited_term.lower().strip()
        # إذا كانت الكلمة المحظورة نفسها بذيئة صريحة، لا نسمح بتجاوزها بالكامل
        if prohibited_clean in ("fuck", "bitch", "cunt", "شرموطة", "قحبة", "كسم", "كسامك", "منيوك"):
            return False

        for t in tokens:
            t_low = t.lower()
            if t_low in self.rules.whitelist:
                if prohibited_clean in t_low and prohibited_clean != t_low:
                    return True
        return False

    @staticmethod
    def _get_arabic_reason_for_category(category: ViolationCategory) -> str:
        if category in (ViolationCategory.EXPLICIT, ViolationCategory.SEXUAL):
            return "🚫 تم رفض الرسالة لاحتوائها على محتوى أو ألفاظ جنسية غير لائقة تتعارض مع سياسة القناة التعليمية."
        elif category in (ViolationCategory.THREAT, ViolationCategory.VIOLENCE):
            return "🚫 تم رفض الرسالة لاحتوائها على تهديدات أو تحريض على العنف."
        elif category == ViolationCategory.SELF_HARM:
            return "🚫 تم رفض الرسالة لاحتوائها على إشارات لإيذاء النفس."
        elif category in (ViolationCategory.HATE, ViolationCategory.SLUR):
            return "🚫 تم رفض الرسالة لاحتوائها على خطاب كراهية أو تمييز."
        elif category in (ViolationCategory.HARASSMENT, ViolationCategory.BULLYING):
            return "🚫 تم رفض الرسالة لاحتوائها على تنمر أو تحرش أو مضايقة للآخرين."
        return "🚫 تم رفض الرسالة لاحتوائها على شتائم أو ألفاظ مسيئة للآخرين."
