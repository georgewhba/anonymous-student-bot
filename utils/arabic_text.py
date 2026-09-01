"""
Arabic text normalization, profanity checking, and duplicate content hashing.
"""
import re
import hashlib
import unicodedata
from typing import List, Tuple, Optional

# قائمة بالكلمات والألفاظ المسيئة الشائعة للتوافق
DEFAULT_PROFANITY_LIST = [
    "قحبة", "شرموطة", "شرموط", "منيك", "منيوك", "كس", "طيز", "عرص", "ديوث",
    "خول", "سافل", "حقير", "زب", "لعنة", "يلعن", "كلب", "ابن الكلب", "ابن الحرام",
    "عاهر", "عاهرة", "قذر", "تفو", "لوطي", "شاذ", "ممحون", "سكس", "بورن",
    "fuck", "shit", "bitch", "asshole", "dick", "pussy", "cunt", "bastard"
]

# نمط التعرف على الروابط ومجموعات تيليجرام
URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s]+|"
    r"t\.me/[^\s]+|"
    r"telegram\.me/[^\s]+|"
    r"@[a-zA-Z0-9_]{4,}",
    re.IGNORECASE
)

# نمط إزالة التشكيل العربي
TASHKEEL_REGEX = re.compile(r"[\u064B-\u065F\u0670]")

# نمط تكرار الحروف لأكثر من مرتين
REPEATED_CHARS_REGEX = re.compile(r"(.)\1{2,}")


def normalize_arabic(text: str) -> str:
    """
    تطبيع النصوص العربية وإزالة التشكيل والهمزات وتوحيد الأحرف
    مع استخدام معيار Unicode NFKC لتنقية الحروف الخاصة.
    """
    if not text:
        return ""

    # توحيد صيغة اليونيكود
    text = unicodedata.normalize("NFKC", text)

    # تحويل للحروف الصغيرة للكلمات اللاتينية
    text = text.lower()

    # إزالة علامات التشكيل
    text = TASHKEEL_REGEX.sub("", text)

    # إزالة التطويل (ـ)
    text = text.replace("ـ", "")

    # توحيد الألفات
    text = re.sub(r"[أإآٱ]", "ا", text)

    # توحيد الياء والألف المقصورة
    text = re.sub(r"[ىي]", "ي", text)

    # توحيد التاء المربوطة والهاء
    text = re.sub(r"[ةه]", "ه", text)

    # تقليص الحروف المكررة عمداً
    text = REPEATED_CHARS_REGEX.sub(r"\1\1", text)

    return text.strip()


def contains_links(text: Optional[str]) -> bool:
    """التحقق هل يحتوي النص على روابط أو معرفات قنوات/مستخدمين"""
    if not text:
        return False
    return bool(URL_REGEX.search(text))


def check_profanity(
    text: Optional[str],
    custom_blacklist: Optional[List[str]] = None
) -> Tuple[bool, Optional[str]]:
    """
    فحص النص بحثاً عن كلمات بذيئة أو مسيئة
    يرجع: (is_profane, matched_word)
    """
    if not text:
        return False, None

    normalized = normalize_arabic(text)
    word_list = custom_blacklist or DEFAULT_PROFANITY_LIST

    cleaned_chars = re.sub(r"[^\w\s]", "", normalized)
    compact_text = cleaned_chars.replace(" ", "")

    for word in word_list:
        norm_word = normalize_arabic(word)
        if re.search(rf"\b{re.escape(norm_word)}\b", normalized):
            return True, word
        if len(norm_word) >= 4 and norm_word in compact_text:
            return True, word

    return False, None


def compute_content_hash(text: Optional[str], media_id: Optional[str] = None) -> str:
    """
    توليد هاش فريد للمحتوى لمكافحة إرسال الرسائل والردود المكررة
    """
    base = ""
    if text:
        base += normalize_arabic(text)
    if media_id:
        base += f"_{media_id}"

    if not base:
        return ""

    return hashlib.sha256(base.encode("utf-8")).hexdigest()
