"""
Advanced Multi-Representation Text Normalizer.
Provides deep normalization across Unicode, Arabic, English, Arabizi, Leetspeak,
Homoglyphs, and Spacing/Punctuation obfuscations while preserving the original user text.
"""
import re
import unicodedata
from typing import List, Set
from moderation.models import NormalizedTextBundle

# أحرف الزيرو ويدث والمحارف المخفية
ZERO_WIDTH_REGEX = re.compile(
    r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u00AD\uFE00-\uFE0F\uFFF9-\uFFFB]"
)

# علامات التشكيل العربية وعلامات المصحف
TASHKEEL_REGEX = re.compile(
    r"[\u064B-\u065F\u0670\u0610-\u061A\u06D6-\u06DC\u06DF-\u06E8\u06EA-\u06ED]"
)

# تكرار الحروف لأكثر من مرتين
REPEATED_CHARS_REGEX = re.compile(r"(.)\1{2,}")

# تكرار الحروف لأكثر من مرة (لإزالة التكرار بالكامل)
COLLAPSE_SINGLE_REGEX = re.compile(r"(.)\1+")

# جدول تحويل الفرنكو / Arabizi (بما في ذلك الحركات المركبة مثل 3' و 7')
ARABIZI_COMPOSITE = [
    ("3'", "غ"),
    ("7'", "خ"),
    ("6'", "ظ"),
    ("2'", "ض"),
    ("s'", "ص"),
    ("t'", "ط"),
    ("d'", "ض"),
    ("th", "ث"),
    ("kh", "خ"),
    ("gh", "غ"),
    ("sh", "ش"),
]

ARABIZI_SINGLE_MAP = {
    '3': 'ع',
    '7': 'ح',
    '5': 'خ',
    '8': 'غ',
    '9': 'ق',
    '2': 'ء',
    '6': 'ط',
    '4': 'ش',
    '1': 'ي'
}

# جدول الحروف اللاتينية المشابهة للإنجليزية (Leetspeak)
LEETSPEAK_MAP = {
    '4': 'a',
    '@': 'a',
    '3': 'e',
    '1': 'i',
    '!': 'i',
    '|': 'i',
    '0': 'o',
    '5': 's',
    '$': 's',
    '7': 't',
    '+': 't',
    '8': 'b',
    '9': 'g',
    'v': 'u',
}

# جدول الحروف الكريلية واليونانية المشابهة بصرياً للاتينية (Homoglyphs)
HOMOGLYPH_MAP = {
    # Cyrillic -> Latin
    '\u0430': 'a', '\u0410': 'A',  # а, А
    '\u0435': 'e', '\u0415': 'E',  # е, Е
    '\u0454': 'e', '\u0404': 'E',  # є, Є
    '\u043E': 'o', '\u041E': 'O',  # о, О
    '\u0440': 'p', '\u0420': 'P',  # р, Р
    '\u0441': 'c', '\u0421': 'C',  # с, С
    '\u0443': 'y', '\u0423': 'Y',  # у, У
    '\u0445': 'x', '\u0425': 'X',  # х, Х
    '\u0456': 'i', '\u0406': 'I',  # і, І
    '\u0457': 'i', '\u0407': 'I',  # ї, Ї
    '\u0458': 'j', '\u0408': 'J',  # ј, Ј
    '\u0455': 's', '\u0405': 'S',  # ѕ, Ѕ
    '\u04bb': 'h', '\u04ba': 'H',  # һ, Һ
    '\u0412': 'B', '\u041A': 'K',  # В, К
    '\u041C': 'M', '\u041D': 'H',  # М, Н
    '\u0422': 'T',                  # Т
    # Greek -> Latin
    '\u03B1': 'a', '\u0391': 'A',  # α, Α
    '\u03B2': 'b', '\u0392': 'B',  # β, Β
    '\u03B5': 'e', '\u0395': 'E',  # ε, Ε
    '\u03BF': 'o', '\u039F': 'O',  # ο, Ο
    '\u03C1': 'p', '\u03A1': 'P',  # ρ, Ρ
    '\u03C4': 't', '\u03A4': 'T',  # τ, Τ
    '\u03C5': 'u', '\u03A5': 'Y',  # υ, Υ
    '\u03C7': 'x', '\u03A7': 'X',  # χ, Χ
}


class TextNormalizer:
    """محرك تطبيع النصوص الشامل متعدد الطبقات"""

    @staticmethod
    def strip_zero_width(text: str) -> str:
        """إزالة المحارف المخفية ومحارف الزيرو ويدث"""
        if not text:
            return ""
        return ZERO_WIDTH_REGEX.sub("", text)

    @staticmethod
    def normalize_unicode(text: str) -> str:
        """تطبيع اليونيكود عبر معيار NFKC وتنقية الرموز الخاصة"""
        if not text:
            return ""
        text = TextNormalizer.strip_zero_width(text)
        return unicodedata.normalize("NFKC", text)

    @staticmethod
    def de_homoglyph(text: str) -> str:
        """استبدال الحروف المتشابهة بصرياً بأحرف لاتينية قياسية"""
        if not text:
            return ""
        res = []
        for ch in text:
            res.append(HOMOGLYPH_MAP.get(ch, ch))
        return "".join(res)

    @staticmethod
    def normalize_arabic(text: str) -> str:
        """
        تطبيع النصوص العربية للتحليل:
        - إزالة التشكيل والتطويل
        - توحيد الهمزات والياء والتاء المربوطة
        - تقليص تكرار الحروف المبالغ فيه
        """
        if not text:
            return ""

        # 1. إزالة التشكيل والتطويل والمحارف المخفية
        text = ZERO_WIDTH_REGEX.sub("", text)
        text = TASHKEEL_REGEX.sub("", text)
        text = text.replace("ـ", "")

        # 2. توحيد الهمزات والألفات
        text = re.sub(r"[أإآٱ]", "ا", text)
        text = re.sub(r"[ىيئ]", "ي", text)
        text = re.sub(r"[ةه]", "ه", text)
        text = re.sub(r"[ؤ]", "و", text)

        # 3. تقليص التكرار المتعمد (مثال: ككللللمة -> كلمة)
        text = REPEATED_CHARS_REGEX.sub(r"\1\1", text)

        return text

    @staticmethod
    def de_leetspeak(text: str) -> str:
        """فك تشفير التبديلات الرقمية والرمزية في الإنجليزية (f4ck -> fack)"""
        if not text:
            return ""
        text_lower = text.lower()
        res = []
        for ch in text_lower:
            res.append(LEETSPEAK_MAP.get(ch, ch))
        return "".join(res)

    @staticmethod
    def de_arabizi(text: str) -> str:
        """تحويل نصوص الفرنكو/Arabizi إلى المقابل الصوتي العربي"""
        if not text:
            return ""
        res = text.lower()

        # 1. استبدال التراكيب المركبة أولاً
        for lat_comp, ar_char in ARABIZI_COMPOSITE:
            res = res.replace(lat_comp, ar_char)

        # 2. استبدال الأرقام الفردية
        chars = []
        for ch in res:
            chars.append(ARABIZI_SINGLE_MAP.get(ch, ch))
        return "".join(chars)

    @staticmethod
    def create_compact(text: str) -> str:
        """إنشاء تمثيل مضغوط بدون فواصل أو مسافات أو علامات ترقيم أو شرطات سفلية"""
        if not text:
            return ""
        return re.sub(r"[^a-zA-Z0-9\u0600-\u06FF]", "", text)

    @classmethod
    def process(cls, raw_text: str) -> NormalizedTextBundle:
        """
        بناء حزمة تمثيلات كاملة (NormalizedTextBundle)
        تغطي مختلف استراتيجيات التمويه والمراوغة
        """
        if not raw_text:
            return NormalizedTextBundle(
                original="", cleaned="", normalized_ar="", compact_ar="",
                compact_collapsed="", letters_only="", de_leetspeak="",
                compact_leet="", compact_leet_collapsed="",
                de_arabizi="", compact_arab="", compact_arab_collapsed="",
                de_homoglyphs=""
            )

        # 1. التنظيف الأولي وتطبيع اليونيكود
        cleaned = cls.normalize_unicode(raw_text).strip()

        # 2. معالجة الـ Homoglyphs
        homo_clean = cls.de_homoglyph(cleaned)

        # 3. التطبيع العربي
        norm_ar = cls.normalize_arabic(homo_clean)

        # 4. فك تشفير Leetspeak والفرنكو
        de_leet = cls.de_leetspeak(homo_clean)
        de_arab = cls.de_arabizi(norm_ar)

        # 5. التمثيلات المضغوطة بدون فواصل
        compact_ar = cls.create_compact(norm_ar)
        compact_collapsed = COLLAPSE_SINGLE_REGEX.sub(r"\1", compact_ar)

        compact_leet = cls.create_compact(de_leet)
        compact_leet_collapsed = COLLAPSE_SINGLE_REGEX.sub(r"\1", compact_leet)

        compact_arab = cls.create_compact(de_arab)
        compact_arab_collapsed = COLLAPSE_SINGLE_REGEX.sub(r"\1", compact_arab)

        letters_only = re.sub(r"[^a-zA-Z\u0600-\u06FF]", "", norm_ar)

        # 6. تفكيك الرموز إلى كلمات (Tokens)
        tokens = [t for t in re.split(r"[\s\W_]+", norm_ar) if t]
        tokens_leet = [t for t in re.split(r"[\s\W_]+", de_leet) if t]
        tokens_arab = [t for t in re.split(r"[\s\W_]+", de_arab) if t]
        tokens_homo = [t for t in re.split(r"[\s\W_]+", homo_clean.lower()) if t]
        all_tokens = list(dict.fromkeys(tokens + tokens_leet + tokens_arab + tokens_homo))

        # 7. استخراج N-grams للأحرف للبحث الضبابي السريع
        ngrams: Set[str] = set()
        clean_no_space = compact_ar
        for n in (3, 4, 5):
            for i in range(len(clean_no_space) - n + 1):
                ngrams.add(clean_no_space[i:i + n])

        phonetic_variants = list(dict.fromkeys([
            norm_ar,
            de_leet,
            de_arab,
            homo_clean.lower(),
            letters_only
        ]))

        compact_variants = list(dict.fromkeys([
            compact_ar,
            compact_collapsed,
            compact_leet,
            compact_leet_collapsed,
            compact_arab,
            compact_arab_collapsed
        ]))

        return NormalizedTextBundle(
            original=raw_text,
            cleaned=cleaned,
            normalized_ar=norm_ar,
            compact_ar=compact_ar,
            compact_collapsed=compact_collapsed,
            letters_only=letters_only,
            de_leetspeak=de_leet,
            compact_leet=compact_leet,
            compact_leet_collapsed=compact_leet_collapsed,
            de_arabizi=de_arab,
            compact_arab=compact_arab,
            compact_arab_collapsed=compact_arab_collapsed,
            de_homoglyphs=homo_clean,
            phonetic_variants=phonetic_variants,
            compact_variants=compact_variants,
            tokens=all_tokens,
            char_ngrams=ngrams
        )
