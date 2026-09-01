"""
Homoglyphs, Unicode Confusables, and Bounded Fuzzy Matching Tests.
"""
import pytest
from moderation.engine import moderation_engine
from moderation.models import ModerationAction
from moderation.fuzzy import bounded_levenshtein, normalized_similarity, is_fuzzy_match


def test_cyrillic_and_greek_homoglyphs():
    """اختبار كشف الأحرف المتشابهة بصرياً من لغات أخرى (Cyrillic & Greek)"""
    # Cyrillic letters looking like Latin: а (\u0430), о (\u043e), р (\u0440), с (\u0441), е (\u0435)
    cyrillic_attacks = [
        "\u0430\u0455\u0455\u04bb\u043e\u0441\u0435",  # asshole disguised in cyrillic
        "f\u0443ck",                                    # fuck with cyrillic у
        "b\u0456tch",                                   # bitch with cyrillic і
        "p\u043ern",                                    # porn with cyrillic е/o
    ]
    for attack in cyrillic_attacks:
        res = moderation_engine.inspect_content(attack)
        assert res.is_allowed is False, f"فشل كشف هجوم Homoglyph: '{attack}'"
        assert res.action == ModerationAction.BLOCK


def test_damerau_levenshtein_transposition():
    """اختبار كشف تبديل الأحرف المتجاورة (Adjacent Transpositions)"""
    # تبديل حرفين متجاورين
    transposed = [
        "fukc you",      # fuck -> fukc
        "btich please",  # bitch -> btich
        "stuf",          # stfu -> stuf
        "ksoomak",       # kosomak -> ksoomak
    ]
    for t in transposed:
        res = moderation_engine.inspect_content(t)
        assert res.is_allowed is False, f"فشل كشف الكلمة مع تبديل الحروف: '{t}'"
        assert res.action == ModerationAction.BLOCK


def test_fuzzy_length_dependent_thresholds():
    """التأكد من أن الكلمات القصيرة جداً لا تطابق ضبابياً لمنع الإيجابيات الكاذبة"""
    # كلمة قصيرة: 'sex' -> 'six' أو 'sax' يجب ألا تطابق
    matched, _ = is_fuzzy_match("six", "sex")
    assert matched is False

    matched, _ = is_fuzzy_match("tax", "sex")
    assert matched is False

    # كلمة طويلة: 'bastard' -> 'bastrad' يجب أن تطابق
    matched_long, sim = is_fuzzy_match("bastrad", "bastard")
    assert matched_long is True
    assert sim >= 0.75


def test_academic_vocabulary_not_false_positived():
    """التأكد من أن الكلمات الأكاديمية والإنجليزية لا تُحظر بسبب تشابه جزئي"""
    academic_words = [
        "assessment", "assessing", "assistant", "assistance",
        "classic", "classroom", "classes",
        "document", "documentation",
        "compass", "passion", "passive",
        "discussion", "discussing",
        "association", "associate",
        "analysis", "analytic",
        "أكبر", "التقويم", "كتاب", "عكس", "انكسار", "مسألة"
    ]
    for word in academic_words:
        res = moderation_engine.inspect_content(f"سؤال حول موضوع {word}")
        assert res.is_allowed is True, f"كلمة أكاديمية تم حظرها بالخطأ: '{word}'"
        assert res.action == ModerationAction.ALLOW
