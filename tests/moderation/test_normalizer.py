"""
Normalizer Unit Tests.
Verifies multi-representation normalization across Unicode, Arabic, English,
Arabizi, Leetspeak, Homoglyphs, Zero-Width characters, and Obfuscation.
"""
import pytest
from moderation.normalizer import TextNormalizer
from moderation.models import NormalizedTextBundle


def test_arabic_tashkeel_and_tatweel_removal():
    raw = "كَلِمَـــــةٌ طَيِّبَــــةٌ"
    norm = TextNormalizer.normalize_arabic(raw)
    assert "ـ" not in norm
    assert "َ" not in norm
    assert "ٌ" not in norm
    assert "كلمه طيبه" == norm


def test_arabic_letter_unification():
    raw = "أحمد وإبراهيم وآمنة وٱمرؤ ومستشفى وقضاة"
    norm = TextNormalizer.normalize_arabic(raw)
    assert "احمد" in norm
    assert "ابراهيم" in norm
    assert "امنه" in norm
    assert "مستشفي" in norm
    assert "قضاه" in norm


def test_zero_width_and_invisible_character_stripping():
    # كلمة شتيمة محشوة بمحارف ZWSP (\u200b) و ZWJ (\u200d) و BOM (\ufeff)
    invis = "ش\u200Bت\u200Dي\uFEFFم\u200Cة"
    stripped = TextNormalizer.strip_zero_width(invis)
    assert stripped == "شتيمة"
    assert "\u200B" not in stripped
    assert "\uFEFF" not in stripped


def test_spacing_and_punctuation_compact():
    spaced = "ك  ل   م ة"
    punctuated = "ك.ل.م.ة"
    dashed = "ك-ل-م-ة"
    slashed = "ك/ل/م/ة"

    for variant in (spaced, punctuated, dashed, slashed):
        compact = TextNormalizer.create_compact(variant)
        assert compact == "كلمة"


def test_repeated_character_collapse():
    raw_en = "stuuuuuuupid fuuuuuck"
    bundle_en = TextNormalizer.process(raw_en)
    assert "stupid" in bundle_en.normalized_ar or "stuupid" in bundle_en.normalized_ar
    assert "fuck" in bundle_en.normalized_ar or "fuuck" in bundle_en.normalized_ar

    raw_ar = "ككككككللللللمممممة"
    norm_ar = TextNormalizer.normalize_arabic(raw_ar)
    assert len(norm_ar) < len(raw_ar)


def test_english_leetspeak_deobfuscation():
    leet = "f4ck th!$ $h1t"
    de_leet = TextNormalizer.de_leetspeak(leet)
    assert "fack" in de_leet
    assert "thi" in de_leet
    assert "shit" in de_leet


def test_arabizi_franco_normalization():
    franco1 = "kosomak"
    de1 = TextNormalizer.de_arabizi(franco1)
    assert "kosomak" in de1

    franco2 = "3aars 7a2eer 5awal"
    de2 = TextNormalizer.de_arabizi(franco2)
    assert "ع" in de2
    assert "ح" in de2
    assert "خ" in de2


def test_homoglyph_cyrillic_lookalikes():
    # الأحرف Cyrillic: \u0430 (a), \u043e (o), \u0441 (c)
    cyrillic_word = "\u0441\u0443\u043F\u0435\u0440"  # супер
    cleaned = TextNormalizer.de_homoglyph(cyrillic_word)
    assert "c" in cleaned or "y" in cleaned


def test_full_bundle_processing():
    text = "يـَـا شَــ.ـرْ.مُـ.ـو.طَـ.ـة f*u*c*k"
    bundle: NormalizedTextBundle = TextNormalizer.process(text)

    assert bundle.original == text
    assert len(bundle.compact_ar) > 0
    assert len(bundle.tokens) > 0
    assert "شرموط" in bundle.compact_ar or "شرموطه" in bundle.compact_ar
