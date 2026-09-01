"""
Adversarial Red Team & Evasion Test Suite.
Tests evasion techniques: homoglyphs, zero-width spaces, leetspeak, Arabizi,
Damerau-Levenshtein fuzzy matching, and prompt injection/XSS payloads.
"""
import pytest
from moderation.engine import ModerationEngine
from moderation.models import ViolationCategory
from security.escaping import escape_user_content, build_channel_post_html


@pytest.fixture
def engine():
    return ModerationEngine()


def test_homoglyph_and_zero_width_evasion_blocked(engine):
    """التحقق من كشف الكلمات البذيئة المحشوة بالحروف المتشابهة والمحارف الصفرية"""
    evasion_samples = [
        "يـا قـ ـحـ ـبـ ـة",          # تطويل ومسافات
        "ق\u200bح\u200cب\u200dة",     # محارف صفرية (Zero-width characters)
        "s.h.a.r.m.o.o.t.a",          # نقاط فاصلة
        "sh@rmoota",                  # leetspeak
        "mnayek",                     # Arabizi
    ]
    for sample in evasion_samples:
        res = engine.inspect_content(sample)
        assert res.is_allowed is False, f"فشل كشف العينة التمويهية: {sample}"


def test_html_xss_and_injection_escaping():
    """التحقق من تحييد أي أكواد HTML أو ثغرات XSS في مدخلات المستخدم"""
    malicious_inputs = [
        "<script>alert('XSS')</script>",
        "<a href='https://evil.com'>اضغط هنا</a>",
        "<b>نص غامق مزيف</b><script>fetch('/steal')</script>",
        "Hello </div><div class='fake_admin'>مرحبا",
    ]
    for inp in malicious_inputs:
        escaped = escape_user_content(inp)
        assert "<script>" not in escaped
        assert "<a " not in escaped
        assert "</div>" not in escaped
        assert "&lt;" in escaped or "&gt;" in escaped


def test_channel_post_html_structure_preserves_allowed_markup():
    """التحقق من أن المنشور النهائي يحافظ فقط على وسوم البوت المصرح بها ويعقّم محتوى الطالب"""
    student_anon_id = 150
    user_text = "سؤال مع <script>alert(1)</script> و <b>تنسيق</b>"

    rendered_html = build_channel_post_html(student_anon_id, user_text)

    # التحقق من وجود ترويسة الطالب المصرح بها
    assert "طالب #150" in rendered_html
    # التحقق من تعقيم كود السكريبت
    assert "<script>" not in rendered_html
    assert "&lt;script&gt;" in rendered_html
