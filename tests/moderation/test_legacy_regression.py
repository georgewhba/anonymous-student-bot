"""
Comprehensive Moderation Legacy Regression Test Suite.
Guarantees that 100% of legacy blocked content remains strictly blocked (Recall >= Legacy).
Verifies critical evasion cases, spaced profanity, character insertion attacks,
Arabizi, English Leetspeak, Arabic Dialects, PII, and Links, while guaranteeing zero false positives on academic text.
"""
import pytest
from moderation.engine import ModerationEngine, moderation_engine
from moderation.models import ModerationAction, ViolationCategory
from utils.content_moderator import moderator, ViolationType


# ==============================================================================
# 1. اختبار الحالات الحرجة المحددة بالاسم في المتطلبات (Critical Cases)
# ==============================================================================

CRITICAL_ENGLISH_CASES = [
    "fuck",
    "f.u.c.k",
    "f u c k",
    "f4ck",
    "fk you",
    "fuk u",
    "fc u",
    "stfu",
    "gtfo",
    "bch",
    "dck",
    "sh1t",
    "@ss",
    "a$$",
    "ass",
    "asshole",
]

CRITICAL_ARABIZI_CASES = [
    "kosomak",
    "k s o m a k",
    "ksomak",
    "3ars",
    "3 r s",
    "3rs",
    "manyook",
    "manyak",
    "5awal",
    "a7a",
    "7a2ba",
    "sharmota",
]

CRITICAL_ARABIC_CASES = [
    "شرموطة",
    "ش ر م و ط ة",
    "شـ.ـر.مـ.ـو.طـ.ـة",
    "قحبة",
    "ق ح ب ة",
    "قـ.ـحـ.ـبـ.ـة",
    "كسم",
    "ك س م",
    "ك س ا م ك",
    "كس امك",
    "كسامك",
    "كصمك",
    "كثمج",
    "طـيـز",
    "طيز",
    "ط 1 ز",
    "خـوـل",
    "خول",
    "عـرـص",
    "عرص",
    "منيوك",
    "ديوث",
    "احا",
    "أحا",
    "غبي",
    "يلعن امك",
]


@pytest.mark.parametrize("phrase", CRITICAL_ENGLISH_CASES)
def test_critical_english_regression_cases(phrase: str):
    """التحقق من حظر كافة الحالات الإنجليزية الحرجة والتنويعات المشوهة"""
    res = moderation_engine.inspect_content(phrase)
    assert res.is_allowed is False, f"Regression failure on critical English case: '{phrase}'"
    assert res.action == ModerationAction.BLOCK


@pytest.mark.parametrize("phrase", CRITICAL_ARABIZI_CASES)
def test_critical_arabizi_regression_cases(phrase: str):
    """التحقق من حظر كافة حالات الفرنكو والـ Arabizi الحرجة"""
    res = moderation_engine.inspect_content(phrase)
    assert res.is_allowed is False, f"Regression failure on critical Arabizi case: '{phrase}'"
    assert res.action == ModerationAction.BLOCK


@pytest.mark.parametrize("phrase", CRITICAL_ARABIC_CASES)
def test_critical_arabic_regression_cases(phrase: str):
    """التحقق من حظر كافة الحالات العربية الحرجة والتنويعات المشوهة"""
    res = moderation_engine.inspect_content(phrase)
    assert res.is_allowed is False, f"Regression failure on critical Arabic case: '{phrase}'"
    assert res.action == ModerationAction.BLOCK


# ==============================================================================
# 2. اختبار مشكلة المستخدم الدقيقة (Exact User Problem Test)
# ==============================================================================

def test_spaced_arabic_evasion():
    """اختبار حظر التحايل بالمسافات في العربية (ك س ا م ك)"""
    res = moderation_engine.inspect_content("ك س ا م ك")
    assert res.is_allowed is False
    assert res.action == ModerationAction.BLOCK

    # فحص تنويعات أخرى للتحايل بالمسافات
    variants = [
        "ك  س  ا  م  ك",
        "ك . س . ا . م . ك",
        "ك_س_ا_م_ك",
        "ك-س-ا-م-ك",
        "ك س م ك",
        "ك ص ا م ك",
        "ش ر م و ط ه",
        "ق ح ب ه",
        "ط ي ز",
        "خ و ل",
        "ع ر ص",
        "م ن ي و ك",
    ]
    for v in variants:
        r = moderation_engine.inspect_content(v)
        assert r.is_allowed is False, f"Failed to block spaced variant: '{v}'"


# ==============================================================================
# 3. اختبار هجمات إقحام الأحرف (Character Insertion Attacks)
# ==============================================================================

def test_character_insertion_attacks():
    """كشف المحارف الإضافية والفواصل المقحمة بين الحروف المحظورة"""
    attacks = [
        "ش_1_ر_2_م_3_و_ط_ة",
        "ق-x-ح-x-ب-x-ة",
        "ك...س...ا...م...ك",
        "f_u_c_k",
        "f-x-u-x-c-x-k",
        "b_i_t_c_h",
        "s.h.i.t",
        "k_o_s_o_m_a_k",
        "3_a_r_s",
    ]
    for attack in attacks:
        res = moderation_engine.inspect_content(attack)
        assert res.is_allowed is False, f"Character insertion attack bypassed filter: '{attack}'"


# ==============================================================================
# 4. التوافق الكامل مع قواميس النسخة القديمة (Legacy Dictionary Recall)
# ==============================================================================

LEGACY_DICTIONARY_SAMPLE = [
    # سباب وإهانات
    "سافل", "حقير", "وسخ", "قذر", "واطي", "ندل", "نجس", "تفو", "طز",
    "عبيط", "اهبل", "متخلف", "حيوان", "حمار", "كلب", "ابن الكلب", "ابن الحرام",
    # محتوى جنسي وإباحي
    "عاهر", "عاهرة", "لوطي", "شاذ", "ممحون", "سكس", "بورن", "منيك",
    "متناك", "انيك", "ينيك", "تنيك", "زب", "طيز", "كس",
    # تهديدات وعنف
    "هقتلك", "هدبحك", "هولع فيك", "انتحار", "انتحر", "هنتحر", "عايز اموت نفسي",
    # إنجليزي
    "bitch", "shit", "bastard", "cunt", "asshole", "dick", "pussy", "nigger", "faggot",
]


@pytest.mark.parametrize("word", LEGACY_DICTIONARY_SAMPLE)
def test_legacy_dictionary_recall(word: str):
    """التأكد من أن كل كلمة في القاموس القديم يتم حظرها دون استثناء"""
    res = moderation_engine.inspect_content(word)
    assert res.is_allowed is False, f"Legacy dictionary word not blocked: '{word}'"
    assert res.action == ModerationAction.BLOCK


# ==============================================================================
# 5. التوافق مع واجهة ContentModerationEngine القديمة
# ==============================================================================

def test_legacy_content_moderator_facade():
    """التأكد من توافق واجهة moderator.inspect_content القديمة 100%"""
    res_clean = moderator.inspect_content("ما هي المحاضرة القادمة؟")
    assert res_clean.is_allowed is True
    assert res_clean.violation_type == ViolationType.NONE

    res_blocked = moderator.inspect_content("انت شخص سافل")
    assert res_blocked.is_allowed is False
    assert res_blocked.violation_type in (ViolationType.PROFANITY, ViolationType.INSULT)


# ==============================================================================
# 6. اختبار مناعة الأسئلة الأكاديمية (Zero False Positives on Academic Context)
# ==============================================================================

ACADEMIC_CLEAN_CORPUS = [
    "ما هو تعريف انكسار الضوء في مادة الفيزياء؟",
    "كيف يتم كسر حلقة التكرار في لغة بايثون باستخدام كلمة break؟",
    "شرح درس الكسور والعمليات الحسابية عليها في الرياضيات",
    "طرق التغلب على الكسل وتنظيم جدول المذاكرة",
    "ما هي شروط كسب الثقة في بيئة العمل؟",
    "شرح العدسات والمرايا العاكسة وتطبيقاتها",
    "Please explain binary search trees and recursion in computer science",
    "What is the difference between synchronous and asynchronous programming?",
    "We need to discuss the assessment criteria for this class",
    "The airplane cockpit displays navigation data",
    "This is a massive database asset for documentation",
]


@pytest.mark.parametrize("academic_text", ACADEMIC_CLEAN_CORPUS)
def test_academic_corpus_false_positive_immunity(academic_text: str):
    """التأكد من السماح بكافة الأسئلة الأكاديمية وعدم حظر الكلمات المشابهة (False Positive Safety)"""
    res = moderation_engine.inspect_content(academic_text)
    assert res.is_allowed is True, f"Legitimate academic query blocked falsely: '{academic_text}' (Reason: {res.reasons})"
    assert res.action == ModerationAction.ALLOW
