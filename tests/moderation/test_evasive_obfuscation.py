"""
Adversarial and Evasive Obfuscation Tests.
Verifies that multi-layer obfuscations are blocked while academic text and safe homonyms remain allowed.
"""
import pytest
from moderation.engine import moderation_engine
from moderation.models import ViolationCategory, ModerationAction


def test_clean_academic_questions_allowed_and_no_false_positives():
    """التأكد من أن الأسئلة الأكاديمية والكلمات السليمة المشابهة لا تحظر أبداً (False Positive Protection)"""
    academic_queries = [
        "ما هو تعريف انكسار الضوء في مادة الفيزياء؟",
        "هل يمكن شرح خوارزمية البحث الثنائي وتطبيقها في بايثون؟",
        "كيف يتم كسر حلقة التكرار باستخدام أمر break في البرمجة؟",
        "طرق التغلب على الكسل وتنظيم وقت المذاكرة للامتحانات النهائية",
        "ما هي شروط كسب الثقة في المقابلات الوظيفية؟",
        "شرح تأثير المرايا العاكسة والعدسات في علم البصريات",
        "ما هو الفرق بين الشبكات المحلية والشبكات واسعة النطاق؟",
        "Please explain binary search trees in data structures",
        "What is the difference between synchronous and asynchronous programming?"
    ]

    for q in academic_queries:
        res = moderation_engine.inspect_content(q)
        assert res.is_allowed is True, f"تم حظر سؤال أكاديمي سليم بالخطأ: '{q}' (السبب: {res.reasons})"
        assert res.action == ModerationAction.ALLOW


def test_evasive_arabic_obfuscations_blocked():
    """كشف التحايل بالمسافات وعلامات الترقيم واللهجات والتبديلات الصوتية في العربية"""
    adversarial_arabic = [
        "شـ.ـر.مـ.ـو.طـ.ـة",
        "ش ر م و ط ة",
        "ش_ر_م_و_ط_ه",
        "قـ.ـحـ.ـبـ.ـة",
        "ك.س.م.ك",
        "كثمج",
        "قثمك",
        "كصمك",
        "طـ.ـيـ.ـز",
        "ط 1 ز",
        "5ول وسافل",
        "3رص",
        "مـ.ـنـ.ـيـ.ـوك",
        "يـ.ـلـ.ـعـ.ـن ابوك",
        "يا ابن الشـ.ـرمـ.ـوطـ.ـة",
        "كس اختك يا حيوان"
    ]

    for attack in adversarial_arabic:
        res = moderation_engine.inspect_content(attack)
        assert res.is_allowed is False, f"فشل كشف المحتوى المسيء المموّه: '{attack}'"
        assert res.action == ModerationAction.BLOCK


def test_evasive_english_and_leetspeak_blocked():
    """كشف التحايل بالإنجليزية والأحرف البديلة وعلامات الترقيم"""
    adversarial_english = [
        "f*u*c*k y*o*u",
        "f u c k",
        "f.u.c.k",
        "f4ck you",
        "b!tch",
        "b.i.t.c.h",
        "sh1t",
        "stfu",
        "gtfo",
        "d1ck",
        "p*ssy",
        "c*nt",
        "a$$hole",
        "fuuuuuck this class"
    ]

    for attack in adversarial_english:
        res = moderation_engine.inspect_content(attack)
        assert res.is_allowed is False, f"فشل كشف الإنجليزية المشوهة: '{attack}'"
        assert res.action == ModerationAction.BLOCK


def test_arabizi_franco_blocked():
    """كشف شتائم الفرنكو والـ Arabizi"""
    franco_attacks = [
        "kosomak ya 5awal",
        "sharmota",
        "shrmta",
        "manyook",
        "manyk",
        "3ars",
        "a7a",
        "teez"
    ]

    for attack in franco_attacks:
        res = moderation_engine.inspect_content(attack)
        assert res.is_allowed is False, f"فشل كشف الفرنكو: '{attack}'"
        assert res.action == ModerationAction.BLOCK


def test_mixed_language_abuse_blocked():
    """كشف الشتائم المختلطة بين اللغات"""
    mixed = [
        "انت stupid وحيوان",
        "you are sharmota",
        "what a سافل and idiot",
        "يا خول stfu"
    ]

    for attack in mixed:
        res = moderation_engine.inspect_content(attack)
        assert res.is_allowed is False, f"فشل كشف الشتائم المختلطة: '{attack}'"
        assert res.action == ModerationAction.BLOCK


def test_pii_self_doxxing_blocked():
    """كشف محاولات كشف الهوية الشخصية"""
    pii_samples = [
        "اسمي أحمد محمود وعندي سؤال",
        "my name is john and i need help",
        "رقمي 01012345678 تواصلوا معي",
        "phone: +201099887766",
        "my email is student2026@university.edu.eg",
        "عمري 21 سنة وساكن في مدينة نصر"
    ]

    for pii in pii_samples:
        res = moderation_engine.inspect_content(pii)
        assert res.is_allowed is False, f"فشل حجب تسريب PII: '{pii}'"
        assert res.action == ModerationAction.BLOCK


def test_all_links_blocked():
    """كشف وحظر كافة الروابط والدومينات ومعرفات تيليجرام"""
    links = [
        "https://t.me/joinchat/AbCdEfGh",
        "زوروا موقعنا https://example.com/lecture",
        "www.academia-share.net",
        "انضموا لقناتنا @my_telegram_channel",
        "192.168.1.100"
    ]

    for link in links:
        res = moderation_engine.inspect_content(link)
        assert res.is_allowed is False, f"فشل حجب الرابط: '{link}'"
        assert res.action == ModerationAction.BLOCK
