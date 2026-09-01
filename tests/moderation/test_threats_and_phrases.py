"""
Threats, Harassment, Hate Speech, and Compound Phrases Tests.
"""
import pytest
from moderation.engine import moderation_engine
from moderation.models import ViolationCategory, ModerationAction, SeverityLevel


def test_direct_threats_blocked():
    """اختبار كشف التهديدات المباشرة والتحريض على العنف"""
    threats = [
        "هقتلك يا فلان لو شفتك",
        "ساقتلك قريباً",
        "هدبحك في الكلية",
        "سادبحك واخلص منك",
        "هولع فيك لو جيت",
        "تصفية جسدية لكل من يخالفنا",
        "i will kill you tomorrow",
        "i'm going to kill you",
        "i will hunt you down and destroy you",
        "هفضحك وانشر صورك"
    ]
    for threat in threats:
        res = moderation_engine.inspect_content(threat)
        assert res.is_allowed is False, f"فشل كشف التهديد: '{threat}'"
        assert res.action == ModerationAction.BLOCK
        assert res.category in (ViolationCategory.THREAT, ViolationCategory.VIOLENCE, ViolationCategory.HARASSMENT)
        assert res.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)


def test_sexual_harassment_formulas_blocked():
    """اختبار كشف صيغ التحرش اللفظي وطلب الصور"""
    harassment_samples = [
        "تعالي خاص يا قمر",
        "ابعتي صورك ضروري",
        "send nudes please",
        "send me nudes right now"
    ]
    for sample in harassment_samples:
        res = moderation_engine.inspect_content(sample)
        assert res.is_allowed is False, f"فشل كشف صيغة التحرش: '{sample}'"
        assert res.action == ModerationAction.BLOCK
        assert res.category in (ViolationCategory.HARASSMENT, ViolationCategory.SEXUAL, ViolationCategory.EXPLICIT)


def test_hate_speech_and_blasphemy_blocked():
    """اختبار كشف خطاب الكراهية والازدراء"""
    hate_samples = [
        "يلعن دينك يا كافر",
        "يلعن ربك",
        "يلعن دين اللي جابك",
        "يا كافر يا نجس"
    ]
    for sample in hate_samples:
        res = moderation_engine.inspect_content(sample)
        assert res.is_allowed is False, f"فشل كشف خطاب الكراهية: '{sample}'"
        assert res.action == ModerationAction.BLOCK
        assert res.category in (ViolationCategory.HATE, ViolationCategory.SLUR, ViolationCategory.PROFANITY)


def test_self_harm_and_suicide_blocked():
    """اختبار كشف رسائل الانتحار وإيذاء النفس"""
    self_harm_samples = [
        "أنا هنتحر خلاص ومش قادر أعيش",
        "عايز اموت نفسي تعبت من الامتحانات",
        "بموت نفسي ومش عايز حد يكلمني",
        "i will commit suicide today",
        "i want to kill myself"
    ]
    for sample in self_harm_samples:
        res = moderation_engine.inspect_content(sample)
        assert res.is_allowed is False, f"فشل كشف إيذاء النفس: '{sample}'"
        assert res.action == ModerationAction.BLOCK
        assert res.category == ViolationCategory.SELF_HARM
