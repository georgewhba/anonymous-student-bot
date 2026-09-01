import pytest
from utils.arabic_text import (
    normalize_arabic,
    check_profanity,
    contains_links,
    compute_content_hash
)


def test_arabic_normalization():
    # فحص إزالة التشكيل
    assert normalize_arabic("سَؤَالٌ تَعْلِيمِيٌّ") == "سؤال تعليمي"

    # فحص توحيد الهمزات والألفات
    assert normalize_arabic("إستفسار أستاذ آية") == "استفسار استاذ ايه"

    # فحص الحروف المكررة عمداً
    assert normalize_arabic("كككككككلام") == "ككلام"


def test_link_detection():
    assert contains_links("مرحباً بكم https://example.com/test") is True
    assert contains_links("تابعونا على t.me/my_channel") is True
    assert contains_links("تواصل معي عبر @username_test") is True
    assert contains_links("هذا سؤال عادي بدون أي روابط خارجية") is False


def test_profanity_filter():
    # نص سليم
    is_profane, _ = check_profanity("السلام عليكم، لدي استفسار بخصوص محاضرة الغد")
    assert is_profane is False

    # نص يحتوي على كلمة بذيئة واضحة
    is_profane, word = check_profanity("هذا شخص سافل جداً")
    assert is_profane is True
    assert word == "سافل"

    # نص يحتوي على كلمة مموهة بالتشكيل والحروف المكررة
    is_profane, _ = check_profanity("أنت سسسسسَافِلٌ")
    assert is_profane is True


def test_content_hash_duplicate():
    hash1 = compute_content_hash("ما هو موعد الامتحان النهائي؟")
    hash2 = compute_content_hash("ما هو موعد الامتحان النهائي؟")
    hash3 = compute_content_hash("ما هُو مَوْعِدُ الإمْتِحَانِ النِهَائِي؟")

    assert hash1 == hash2
    assert hash1 == hash3  # بسبب التطبيع العربي الذكي

    diff_hash = compute_content_hash("سؤال مختلف تماماً")
    assert hash1 != diff_hash
