"""
Security, Escaping, and Log Scrubbing Tests.
Tests HTML injection prevention, formatting security, and automated PII log scrubbing.
"""
import logging
from security.escaping import escape_user_content, build_channel_post_html, build_channel_reply_html
from utils.logger import PIIScrubbingFormatter


def test_html_injection_escaping():
    # 1. وسوم HTML خبيثة
    xss_payload = '<script>alert("hacked")</script>'
    escaped = escape_user_content(xss_payload)
    assert "<script>" not in escaped
    assert "&lt;script&gt;" in escaped

    # 2. روابط HTML مموهة
    html_link = '<a href="https://evil.com">اضغط هنا</a>'
    escaped_link = escape_user_content(html_link)
    assert "<a href=" not in escaped_link
    assert "&lt;a" in escaped_link

    # 3. بناء منشور القناة
    post_html = build_channel_post_html(101, '<b onclick="malicious()">سؤال اختبار</b>')
    assert '<b onclick=' not in post_html
    assert "&lt;b" in post_html
    assert "طالب #101" in post_html

    # 4. بناء الرد المجهول
    reply_html = build_channel_reply_html(102, 5001, '<i>رد غير آمن</i>')
    assert "<i>رد" not in reply_html
    assert "&lt;i&gt;" in reply_html
    assert "#5001" in reply_html


def test_pii_log_scrubbing():
    formatter = PIIScrubbingFormatter("%(message)s")

    # 1. تطهير توكن البوت
    record1 = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="Bot started with token 123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ1234567",
        args=(), exc_info=None
    )
    formatted1 = formatter.format(record1)
    assert "123456789:ABCdefGh" not in formatted1
    assert "[REDACTED_BOT_TOKEN]" in formatted1

    # 2. تطهير مفتاح التشفير
    record2 = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="Loaded config ENCRYPTION_KEY=s8zPzX1w2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9=",
        args=(), exc_info=None
    )
    formatted2 = formatter.format(record2)
    assert "s8zPzX1w2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9=" not in formatted2
    assert "ENCRYPTION_KEY=[REDACTED_KEY]" in formatted2

    # 3. تطهير كلمة المرور
    record3 = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="Admin login attempt with password=MySecretPassword123",
        args=(), exc_info=None
    )
    formatted3 = formatter.format(record3)
    assert "MySecretPassword123" not in formatted3
    assert "password=[REDACTED_PASSWORD]" in formatted3
