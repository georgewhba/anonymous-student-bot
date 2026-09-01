"""
Rule Registry and Compiled Regular Expressions.
Pre-compiles high-performance regexes for links, PII, evasive patterns, and abusive phrases.
"""
import re
from typing import Optional, Tuple, List, Dict, Set
from moderation.models import ViolationCategory, SeverityLevel
from moderation.dictionaries import (
    ARABIC_DICTIONARY,
    ENGLISH_DICTIONARY,
    ARABIZI_DICTIONARY,
    ABUSIVE_PHRASES,
    ACADEMIC_WHITELIST_TOKENS
)

# ==============================================================================
# 1. روابط ودومينات وشبكات التواصل (Strict No Links Policy)
# ==============================================================================
ALL_LINKS_REGEX = re.compile(
    r"(?i)("
    r"https?://\S+|"
    r"ftp://\S+|"
    r"t\.me/\S+|"
    r"telegram\.me/\S+|"
    r"discord(?:\.gg|app\.com/invite)/\S+|"
    r"chat\.whatsapp\.com/\S+|"
    r"wa\.me/\S+|"
    r"(?:www\.)?[a-zA-Z0-9-]+\.(?:com|org|net|edu|gov|io|ai|me|ly|gl|app|dev|xyz|site|online|top|info|link|store|tech|ru|cn|eg|sa|ae|uk|de|fr|us)(?:/\S*)?|"
    r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/\S*)?|"
    r"@[a-zA-Z0-9_]{3,32}"
    r")"
)

# ==============================================================================
# 2. البيانات الشخصية (PII / Self-Doxxing)
# ==============================================================================
PHONE_REGEX = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b|"
    r"\b01[0125]\d{8}\b|"
    r"\b05\d{8}\b"
)

EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
)

SELF_NAME_PATTERNS = [
    re.compile(r"(?:اسمي|اسمى|معكم|معاكو|انا الطالب|أنا الطالب|معكم الطالبة|انا الطالبة)\s+([\u0600-\u06FF]{2,}(?:\s+[\u0600-\u06FF]{2,})*)", re.IGNORECASE),
    re.compile(r"\b(?:my name is|i am called|this is)\s+([A-Za-z]+)\b", re.IGNORECASE),
    re.compile(r"\b(?:i['’]?m)\s+(?!going|gonna|trying|writing|asking|here|sorry|fine|not|a|an|the|just|only|currently|feeling|happy|glad|reading|wondering)([A-Z][a-z]+)\b")
]

AGE_PATTERNS = [
    re.compile(r"(?:عمري|عمرى|سني|سنى)\s+\d{1,2}(?:\s*(?:سنة|سنه|عام))?", re.IGNORECASE),
    re.compile(r"\b(?:my age is|i am|i'm)\s+\d{1,2}(?:\s+(?:years old|yo))?\b", re.IGNORECASE)
]

LOCATION_PATTERNS = [
    re.compile(r"(?:ساكن في|ساكن فى|عايش في|عايش فى|عنواني|عنوانى|منطقة|محافظة|شارع)\s+([\u0600-\u06FF]{3,})", re.IGNORECASE)
]

# ==============================================================================
# 3. الأنماط الهيكلية والمشوهة (Evasive Regexes & Spacing/Insertion Attacks)
# ==============================================================================
EVASIVE_PATTERNS_ARABIC: List[Tuple[re.Pattern, ViolationCategory, SeverityLevel]] = [
    # شرموطة وتفرعاتها
    (re.compile(r"[ش][\W_\s\d\u0640]*[ر][\W_\s\d\u0640]*[م][\W_\s\d\u0640]*[و0]*[\W_\s\d\u0640]*[ط][\W_\s\d\u0640]*[ةه]"), ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
    # قحبة وتفرعاتها
    (re.compile(r"[قك][\W_\s\d\u0640]*[ح7][\W_\s\d\u0640]*[ب][\W_\s\d\u0640]*[ةه]"), ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
    # كسمك / كسامك / ك س ا م ك / كصمك / كثمج
    (re.compile(r"[ك][\W_\s\d\u0640]*[س][\W_\s\d\u0640]*[اأإآ]*[\W_\s\d\u0640]*[م][\W_\s\d\u0640]*[ك]"), ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
    (re.compile(r"[ك][\W_\s\d\u0640]*[صث][\W_\s\d\u0640]*[اأإآ]*[\W_\s\d\u0640]*[م][\W_\s\d\u0640]*[كج]"), ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
    # خول وتفرعاتها
    (re.compile(r"(?:\b|^|\s)[خ5][\W_\s\d\u0640]*[و0][\W_\s\d\u0640]*[ل](?:\b|$|\s)"), ViolationCategory.PROFANITY, SeverityLevel.HIGH),
    # عرص وتفرعاتها
    (re.compile(r"(?:\b|^|\s)[ع3][\W_\s\d\u0640]*[ر][\W_\s\d\u0640]*[ص9](?:\b|$|\s)"), ViolationCategory.SEXUAL, SeverityLevel.HIGH),
    # منيوك وتفرعاتها
    (re.compile(r"[م][\W_\s\d\u0640]*[ن][\W_\s\d\u06401]*[يى1][\W_\s\d\u0640]*[و0]*[\W_\s\d\u0640]*[كج]"), ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
    # ديوث وتفرعاتها
    (re.compile(r"[د][\W_\s\d\u06401]*[يى1][\W_\s\d\u0640]*[و0][\W_\s\d\u0640]*[ثست]"), ViolationCategory.SEXUAL, SeverityLevel.HIGH),
    # طيز وتفرعاتها
    (re.compile(r"[ط][\W_\s\d\u06401]*[يى1][\W_\s\d\u06401]*[ز]"), ViolationCategory.EXPLICIT, SeverityLevel.HIGH),
    # زب وتفرعاتها
    (re.compile(r"(?:\b|^|\s)[ز][\W_\s\d\u0640]*[ب][\W_\s\d\u0640]*[يى1]?(?:\b|$|\s)"), ViolationCategory.EXPLICIT, SeverityLevel.HIGH),
    # يلعن امك / يلعن ابوك
    (re.compile(r"[ي][\W_\s\d\u0640]*[ل][\W_\s\d\u0640]*[ع][\W_\s\d\u0640]*[ن][\W_\s\d\u0640]*[اأإآ][\W_\s\d\u0640]*[م][\W_\s\d\u0640]*[ك]"), ViolationCategory.PROFANITY, SeverityLevel.CRITICAL),
    (re.compile(r"[ي][\W_\s\d\u0640]*[ل][\W_\s\d\u0640]*[ع][\W_\s\d\u0640]*[ن][\W_\s\d\u0640]*[اأإآ][\W_\s\d\u0640]*[ب][\W_\s\d\u0640]*[و][\W_\s\d\u0640]*[ك]"), ViolationCategory.PROFANITY, SeverityLevel.CRITICAL),
]

EVASIVE_PATTERNS_ENGLISH: List[Tuple[re.Pattern, ViolationCategory, SeverityLevel]] = [
    # fuck, f u c k, f.u.c.k, f4ck, fyck, etc.
    (re.compile(r"\bf+[\W_*0-9@!$\s]*[u*o0@4yv]+[\W_*0-9@!$\s]*[c*k]+\b", re.IGNORECASE), ViolationCategory.PROFANITY, SeverityLevel.CRITICAL),
    (re.compile(r"\bf+[\W_*0-9@!$\s]*k+\s*(?:you|u)?\b", re.IGNORECASE), ViolationCategory.PROFANITY, SeverityLevel.HIGH),
    (re.compile(r"\bf+[\W_*0-9@!$\s]*u+[\W_*0-9@!$\s]*k+\s*(?:you|u)?\b", re.IGNORECASE), ViolationCategory.PROFANITY, SeverityLevel.HIGH),
    (re.compile(r"\bf+[\W_*0-9@!$\s]*c+\s+(?:you|u)\b", re.IGNORECASE), ViolationCategory.PROFANITY, SeverityLevel.HIGH),
    # bitch, b!tch, btch, bch
    (re.compile(r"\bb+[\W_*0-9@!$\s]*[i*!1]+[\W_*0-9@!$\s]*[t*+]+[\W_*0-9@!$\s]*[c*]*[\W_*0-9@!$\s]*h+\b", re.IGNORECASE), ViolationCategory.PROFANITY, SeverityLevel.HIGH),
    (re.compile(r"\bb+[\W_*0-9@!$\s]*[c*]*[\W_*0-9@!$\s]*h+\b", re.IGNORECASE), ViolationCategory.PROFANITY, SeverityLevel.HIGH),
    # shit, sh1t, s.h.i.t
    (re.compile(r"\bs+[\W_*0-9@!$\s]*[h*]+[\W_*0-9@!$\s]*[i*!1]+[\W_*0-9@!$\s]*[t*+]+\b", re.IGNORECASE), ViolationCategory.PROFANITY, SeverityLevel.HIGH),
    # ass, @ss, a$$hole, asshole
    (re.compile(r"\b[@a]+[\W_*0-9@!$\s]*[s*$5]+[\W_*0-9@!$\s]*[s*$5]+[\W_*0-9@!$\s]*[h*]+[\W_*0-9@!$\s]*[o*0]+[\W_*0-9@!$\s]*[l*|1]+[\W_*0-9@!$\s]*[e*3]+\b", re.IGNORECASE), ViolationCategory.PROFANITY, SeverityLevel.HIGH),
    (re.compile(r"(?:\b|^|\s)[@a]+[\W_*0-9@!$]*[s*$5]+[\W_*0-9@!$]*[s*$5]+(?:\b|$|\s)", re.IGNORECASE), ViolationCategory.PROFANITY, SeverityLevel.HIGH),
    # porn, porno
    (re.compile(r"\bp+[\W_*0-9@!$\s]*[o*0e3@]+[\W_*0-9@!$\s]*[r*]+[\W_*0-9@!$\s]*[n*]+\b", re.IGNORECASE), ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
    # dick, d1ck, dck
    (re.compile(r"\bd+[\W_*0-9@!$\s]*[i*!1]*[\W_*0-9@!$\s]*[c*k]+\b", re.IGNORECASE), ViolationCategory.EXPLICIT, SeverityLevel.HIGH),
    # pussy
    (re.compile(r"\bp+[\W_*0-9@!$\s]*[u*o0@]*[\W_*0-9@!$\s]*[s*$5]+[\W_*0-9@!$\s]*[s*$5]+[\W_*0-9@!$\s]*[y*]+\b", re.IGNORECASE), ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
    # cunt
    (re.compile(r"\bc+[\W_*0-9@!$\s]*[u*o0@4]*[\W_*0-9@!$\s]*n+[\W_*0-9@!$\s]*t+\b", re.IGNORECASE), ViolationCategory.PROFANITY, SeverityLevel.CRITICAL),
    # kosomak, k s o m a k, ksomak
    (re.compile(r"\bk+[\W_*0-9@!$\s]*[o0]*[\W_*0-9@!$\s]*s+[\W_*0-9@!$\s]*[o0]*[\W_*0-9@!$\s]*m+[\W_*0-9@!$\s]*[a@]*[\W_*0-9@!$\s]*k+\b", re.IGNORECASE), ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
    # 3ars, 3 r s, 3rs
    (re.compile(r"(?:\b|^|\s)3+[\W_*0-9@!$\s]*[a@]*[\W_*0-9@!$\s]*r+[\W_*0-9@!$\s]*[s5]+(?:\b|$|\s)", re.IGNORECASE), ViolationCategory.SEXUAL, SeverityLevel.HIGH),
    # manyook, manyak
    (re.compile(r"\bm+[\W_*0-9@!$\s]*[a@]*[\W_*0-9@!$\s]*n+[\W_*0-9@!$\s]*[y*]+[\W_*0-9@!$\s]*[o0]*[\W_*0-9@!$\s]*[o0]*[\W_*0-9@!$\s]*[k]+\b", re.IGNORECASE), ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
    (re.compile(r"\bm+[\W_*0-9@!$\s]*[a@]*[\W_*0-9@!$\s]*n+[\W_*0-9@!$\s]*[y*]+[\W_*0-9@!$\s]*[a@]*[\W_*0-9@!$\s]*[k]+\b", re.IGNORECASE), ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
]


class RuleRegistry:
    """سجل القواعد الرقابية الشامل"""

    def __init__(self):
        self.arabic_terms = list(ARABIC_DICTIONARY)
        self.english_terms = list(ENGLISH_DICTIONARY)
        self.arabizi_terms = list(ARABIZI_DICTIONARY)
        self.phrases = list(ABUSIVE_PHRASES)
        self.whitelist = set(ACADEMIC_WHITELIST_TOKENS)

        # بناء أنماط إدراج الأحرف التلقائية للكلمات الحساسة (Character Insertion Patterns)
        self.insertion_patterns: List[Tuple[re.Pattern, ViolationCategory, SeverityLevel, str]] = []
        self._build_insertion_patterns()

    def _build_insertion_patterns(self):
        """توليد أنماط فحص إدراج الأحرف والمحارف الفاصلة بشكل مقيد ومسبق التجميع"""
        critical_stems = [
            ("شرموط", ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
            ("قحب", ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
            ("كسم", ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
            ("كسامك", ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
            ("طيز", ViolationCategory.EXPLICIT, SeverityLevel.HIGH),
            ("خول", ViolationCategory.PROFANITY, SeverityLevel.HIGH),
            ("عرص", ViolationCategory.SEXUAL, SeverityLevel.HIGH),
            ("منيوك", ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
            ("ديوث", ViolationCategory.SEXUAL, SeverityLevel.HIGH),
            ("احا", ViolationCategory.PROFANITY, SeverityLevel.HIGH),
            ("fuck", ViolationCategory.PROFANITY, SeverityLevel.CRITICAL),
            ("bitch", ViolationCategory.PROFANITY, SeverityLevel.CRITICAL),
            ("shit", ViolationCategory.PROFANITY, SeverityLevel.HIGH),
            ("dck", ViolationCategory.EXPLICIT, SeverityLevel.HIGH),
            ("dick", ViolationCategory.EXPLICIT, SeverityLevel.HIGH),
            ("kosomak", ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
            ("3ars", ViolationCategory.SEXUAL, SeverityLevel.HIGH),
            ("manyook", ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
            ("manyak", ViolationCategory.EXPLICIT, SeverityLevel.CRITICAL),
        ]
        for term, cat, sev in critical_stems:
            chars = [re.escape(c) for c in term]
            # يسمح بفاصل من 0 إلى 3 محارف فاصلة أو مشوشة بين كل حرفين
            pat_str = r"[\s\W_\d\u0640a-zA-Z]{0,3}?".join(chars)
            compiled = re.compile(rf"(?:^|\s|\b|[\W_]){pat_str}(?:$|\s|\b|[\W_])", re.IGNORECASE)
            self.insertion_patterns.append((compiled, cat, sev, term))

    def match_links(self, text: str) -> Optional[Tuple[ViolationCategory, SeverityLevel, str]]:
        match = ALL_LINKS_REGEX.search(text)
        if match:
            return ViolationCategory.LINK, SeverityLevel.HIGH, match.group(0)
        return None

    def match_pii(self, text: str) -> Optional[Tuple[ViolationCategory, SeverityLevel, str, str]]:
        """فحص تسريب البيانات الشخصية"""
        # 1. هواتف
        phone = PHONE_REGEX.search(text)
        if phone:
            digits = re.sub(r"\D", "", phone.group(0))
            if len(digits) >= 8:
                return ViolationCategory.PHONE_NUMBER, SeverityLevel.HIGH, phone.group(0), "🔒 يمنع نشر أرقام الهواتف داخل الأسئلة والمشاركات."

        # 2. بريد
        email = EMAIL_REGEX.search(text)
        if email:
            return ViolationCategory.EMAIL_ADDRESS, SeverityLevel.HIGH, email.group(0), "🔒 يمنع نشر عناوين البريد الإلكتروني."

        # 3. اسم شخصي
        for pat in SELF_NAME_PATTERNS:
            m = pat.search(text)
            if m:
                name = m.group(1).strip()
                if len(name) >= 2:
                    return ViolationCategory.PII_SELF_DOXX, SeverityLevel.HIGH, name, "🔒 يمنع الإفصاح عن اسمك الحقيقي حفاظاً على خصوصيتك."

        # 4. عمر أو موقع
        for pat in AGE_PATTERNS + LOCATION_PATTERNS:
            m = pat.search(text)
            if m:
                return ViolationCategory.PII_SELF_DOXX, SeverityLevel.MEDIUM, m.group(0), "🔒 يمنع ذكر بيانات شخصية حساسة مثل العمر أو العنوان."

        return None

    def match_evasive_patterns(self, text: str) -> Optional[Tuple[ViolationCategory, SeverityLevel, str]]:
        for pat, cat, sev in EVASIVE_PATTERNS_ARABIC + EVASIVE_PATTERNS_ENGLISH:
            m = pat.search(text)
            if m:
                return cat, sev, m.group(0)
        return None

    def match_character_insertion(self, text: str) -> Optional[Tuple[ViolationCategory, SeverityLevel, str, str]]:
        """فحص الكلمات المحظورة ذات المحارف المقحمة بين الحروف الأصلية"""
        for pat, cat, sev, term in self.insertion_patterns:
            m = pat.search(text)
            if m:
                return cat, sev, m.group(0), term
        return None

    def match_phrases(self, text: str) -> Optional[Tuple[ViolationCategory, SeverityLevel, str]]:
        text_lower = text.lower()
        for phrase_entry in self.phrases:
            phrase = phrase_entry["phrase"].lower()
            if phrase in text_lower:
                return phrase_entry["cat"], phrase_entry["sev"], phrase
        return None
