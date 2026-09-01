import pytest
from utils.content_moderator import moderator, ViolationType
from utils.strike_manager import SecurityShield


def test_clean_academic_questions_allowed():
    clean_questions = [
        "ما هو تعريف الخوارزميات في مادة هندسة البرمجيات؟",
        "هل يمكن لأحد شرح طريقة حل المسألة رقم 5 في الشيت؟",
        "متى موعد تسليم مشروع التخرج النهائي؟",
        "ما هو الفرق بين التشفير المتماثل والتشفير غير المتماثل؟",
        "Please explain binary search trees in Python"
    ]
    for q in clean_questions:
        res = moderator.inspect_content(q)
        assert res.is_allowed is True
        assert res.violation_type == ViolationType.NONE


def test_self_doxxing_name_leak_blocked():
    name_leaks = [
        "اسمي أحمد محمود وعندي سؤال في مادة الرياضيات",
        "معكم الطالبة سارة علي وأريد ملخص المحاضرة",
        "انا الطالب محمد مصطفى وأبحث عن زميل للمشروع",
        "my name is John and I have a question"
    ]
    for leak in name_leaks:
        res = moderator.inspect_content(leak)
        assert res.is_allowed is False
        assert res.violation_type == ViolationType.PII_SELF_DOXX
        assert "اسمي" in res.reason_ar or "خصوصيتك" in res.reason_ar or "اسمك" in res.reason_ar


def test_self_doxxing_age_and_location_blocked():
    leaks = [
        "عمري 20 سنة وأدرس في الفرقة الثانية",
        "سني 19 وأريد نصيحة في التخصص",
        "ساكن في المعادي وأبحث عن مجموعة مذاكرة",
        "عايش في مدينة نصر بالقرب من الكلية",
        "my age is 21 and i need help"
    ]
    for leak in leaks:
        res = moderator.inspect_content(leak)
        assert res.is_allowed is False
        assert res.violation_type == ViolationType.PII_SELF_DOXX


def test_phone_number_leak_blocked():
    phone_samples = [
        "تواصلوا معي على رقم 01012345678 للضرورة",
        "رقم الواتساب هو 01298765432 لأي استفسار",
        "الاتصال على +201155443322",
        "هاتفي 0501234567 بالسعودية",
        "01511223344"
    ]
    for p in phone_samples:
        res = moderator.inspect_content(p)
        assert res.is_allowed is False
        assert res.violation_type == ViolationType.PHONE_NUMBER


def test_email_leak_blocked():
    email_samples = [
        "أرسلوا الملف على student.2026@university.edu.eg",
        "بريدي الإلكتروني هو test.user@gmail.com",
        "contact me at my_email@outlook.com"
    ]
    for e in email_samples:
        res = moderator.inspect_content(e)
        assert res.is_allowed is False
        assert res.violation_type == ViolationType.EMAIL_ADDRESS


def test_all_links_completely_blocked():
    link_samples = [
        "تابعوا ملخصات المواد عبر قناتنا https://t.me/student_helpers",
        "زوروا هذا الموقع المفيد www.free-courses-online.org",
        "حسابي على انستغرام هو instagram.com/student_dev",
        "ملفي الشخصي فيسبوك fb.com/profile123",
        "رابط الشات t.me/joinchat/ABCxyz123",
        "تواصلوا معي على تليجرام @student_alex_99",
        "سيرفر الديسكورد https://discord.gg/study2026",
        "الموقع هو https://google.com للبحث",
        "المصدر من http://wikipedia.org/wiki/Algorithm",
        "دومين مباشر بدون بروتوكول: coursera.org/learn/python",
        "رابط مختصر: bit.ly/3xYzA12",
        "عنوان خادم مباشر: 192.168.1.1:8080/file",
        "دومين تعليمي: mit.edu/courses/cs101"
    ]
    for l in link_samples:
        res = moderator.inspect_content(l)
        assert res.is_allowed is False
        assert res.violation_type in [ViolationType.LINK, ViolationType.SOCIAL_LINK]


def test_sexual_and_nsfw_blocked():
    samples = [
        "هذا محتوى سكس غير لائق",
        "فيديو بـ.ـو.ر.ن ممنوع",
        "شخص شـ.ـر.مـ.ـو.ط وسافل",
        "fuck you all bitch"
    ]
    for s in samples:
        res = moderator.inspect_content(s)
        assert res.is_allowed is False
        assert res.violation_type in [ViolationType.SEXUAL, ViolationType.EXPLICIT, ViolationType.SEXUAL_NSFW, ViolationType.PROFANITY]


def test_franco_and_leetspeak_profanity_blocked():
    samples = [
        "enta sharmota ya 7mar",
        "ya manyook",
        "ya 5awal"
    ]
    for s in samples:
        res = moderator.inspect_content(s)
        assert res.is_allowed is False
        assert res.violation_type in [ViolationType.PROFANITY, ViolationType.SEXUAL, ViolationType.EXPLICIT, ViolationType.SEXUAL_NSFW]


def test_evasive_abbreviations_blocked():
    evasive_samples = [
        "fk you man",
        "fuk u all",
        "fc u",
        "fck you",
        "stfu please",
        "you are a btch",
        "bch stop talking",
        "what a sh1t idea",
        "ya كثمج",
        "ya كصمك",
        "يا 5ول",
        "يا 3رص"
    ]
    for sample in evasive_samples:
        res = moderator.inspect_content(sample)
        assert res.is_allowed is False, f"Failed to block evasive profanity: {sample}"
        assert res.violation_type in [ViolationType.PROFANITY, ViolationType.SEXUAL, ViolationType.EXPLICIT, ViolationType.SEXUAL_NSFW]


def test_flood_and_rate_shield():
    uid = 987654321
    # إرسال 3 رسائل طبيعية
    assert SecurityShield.check_rate_and_flood(uid)[0] is True
    assert SecurityShield.check_rate_and_flood(uid)[0] is True
    assert SecurityShield.check_rate_and_flood(uid)[0] is True
    # الرابعة فوراً في أقل من 6 ثوانٍ يتم حظرها بالدرع
    assert SecurityShield.check_rate_and_flood(uid)[0] is False
