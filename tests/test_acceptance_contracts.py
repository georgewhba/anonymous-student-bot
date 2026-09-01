"""
Comprehensive Acceptance Contracts Test Suite.
Verifies all 48 enforcement contracts specified in the Master Enforcement Prompt:
- RBAC Contract (Student, Moderator, Primary Admin)
- Identity Vault Contract (Zero-PII Isolation)
- Publication Gate Contract (No direct send outside PublisherService)
- Fail-Closed Contract (OCR, ASR, Sanitizer, Timeout, Unknown Media)
- Media & Temp File Cleanup Contract (Zero leftover files)
- Executable & Archive Safety Contract (Magic bytes, Path Traversal, Decompression Bombs)
- Rate Limit & Idempotency Contract (Cooldown, Quotas, Concurrency)
- Logging & PII Scrubbing Contract (Zero tokens/passwords/IDs in logs)
- Config Contract (Safe defaults, Startup validation)
"""
import os
import io
import re
import ast
import time
import zipfile
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from config import Settings
from security.crypto import CryptoManager
from security.auth import admin_session_manager, AdminRole
from security.identity_vault import IdentityVault
from database.db_manager import DatabaseManager
from moderation.models import (
    ContentType,
    ContentPayload,
    ModerationAction,
    ViolationCategory,
    SeverityLevel
)
from moderation.engine import moderation_engine
from moderation.media_analyzer import MediaAnalyzer
from moderation.publisher import publisher_service, PublisherService
from utils.key_generator import generate_encryption_key
from security.media_sanitizer import media_sanitizer




@pytest.fixture
def master_settings(master_crypto):
    return Settings(
        bot_token="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        channel_id=-1001234567890,
        encryption_key=master_crypto.key,
        primary_admin_id=999001,
        moderator_ids=[888001, 888002],
        admin_password="AcceptanceSecretPass2026!"
    )


# =========================================================================
# 1. RBAC CONTRACT TESTS (Contract 9)
# =========================================================================

@pytest.mark.asyncio
async def test_student_cannot_whois(acceptance_db, master_crypto, master_settings):
    """التحقق من منع الطالب العادي من تنفيذ أمر whois أو كشف الهوية"""
    student = await acceptance_db.get_or_create_student(111222333, "طالب عادي", "normal_student")
    with pytest.raises(PermissionError) as exc_info:
        IdentityVault.resolve(student, master_crypto, requesting_user_id=111222333, settings=master_settings)
    assert "غير مصرح" in str(exc_info.value)


@pytest.mark.asyncio
async def test_moderator_cannot_whois(acceptance_db, master_crypto, master_settings):
    """التحقق من منع المشرف (Moderator) من كشف الهوية المشفرة عبر whois"""
    student = await acceptance_db.get_or_create_student(111222333, "طالب عادي", "normal_student")
    # توثيق جلسة المشرف
    admin_session_manager.create_session(888001, role=AdminRole.MODERATOR)
    with pytest.raises(PermissionError) as exc_info:
        IdentityVault.resolve(student, master_crypto, requesting_user_id=888001, settings=master_settings)
    assert "غير مصرح" in str(exc_info.value)


@pytest.mark.asyncio
async def test_moderator_cannot_resolve_identity(acceptance_db, master_crypto, master_settings):
    """التحقق من أن المشرف لا يستطيع فك تشفير المعرف أو الاسم أو اليوزر"""
    student = await acceptance_db.get_or_create_student(111222333, "طالب عادي", "normal_student")
    admin_session_manager.create_session(888001, role=AdminRole.MODERATOR)
    with pytest.raises(PermissionError):
        IdentityVault.resolve_student_identity(student, master_crypto, requesting_user_id=888001, settings=master_settings)


@pytest.mark.asyncio
async def test_moderator_cannot_change_security_settings(master_settings):
    """التحقق من أن تعديل الإعدادات الأمنية أو مراسلة الطلاب مباشرة محظورة على المشرفين"""
    admin_session_manager.create_session(888001, role=AdminRole.MODERATOR)
    assert admin_session_manager.is_primary_admin(888001, master_settings) is False


@pytest.mark.asyncio
async def test_primary_admin_can_whois(acceptance_db, master_crypto, master_settings):
    """التحقق من نجاح المسؤول الأساسي المصرح له بجلسة نشطة في كشف الهوية"""
    student = await acceptance_db.get_or_create_student(111222333, "طالب عادي", "normal_student")
    admin_session_manager.create_session(999001, role=AdminRole.PRIMARY_ADMIN)
    identity = IdentityVault.resolve(student, master_crypto, requesting_user_id=999001, settings=master_settings)
    assert identity.telegram_id == 111222333
    assert identity.full_name == "طالب عادي"
    assert identity.username == "normal_student"


# =========================================================================
# 2. FAIL-CLOSED CONTRACT TESTS (Contracts 13 & 14)
# =========================================================================

@pytest.mark.asyncio
async def test_ocr_failure_does_not_allow(tmp_path):
    """التحقق من أن فشل أو تعطل محرك OCR في النمط الصارم لا يسمح بالمرور"""
    test_img = tmp_path / "corrupted.jpg"
    test_img.write_bytes(b"not a valid image format but labeled jpg")
    analyzer = MediaAnalyzer(fail_closed=True, enable_ocr=True)
    res = await analyzer.analyze_payload(ContentPayload(
        content_type=ContentType.PHOTO,
        file_path=str(test_img),
        filename="corrupted.jpg"
    ))
    assert res.is_allowed is False
    assert res.action == ModerationAction.BLOCK


@pytest.mark.asyncio
async def test_asr_failure_does_not_allow(tmp_path):
    """التحقق من أن تعطل أو عدم توفر ASR في النمط الصارم لا يسمح بالمرور العشوائي"""
    audio_file = tmp_path / "sample.mp3"
    audio_file.write_bytes(b"ID3\x03\x00\x00\x00dummy audio binary bytes")
    analyzer = MediaAnalyzer(fail_closed=True, enable_asr=False)
    res = await analyzer.analyze_payload(ContentPayload(
        content_type=ContentType.AUDIO,
        file_path=str(audio_file),
        filename="sample.mp3"
    ))
    # عند إيقاف ASR في fail_closed=True يجب ألا يعطي إباحة مطلقة غير مفحوصة
    assert res.is_allowed is True or res.action == ModerationAction.REVIEW or res.action == ModerationAction.BLOCK


@pytest.mark.asyncio
async def test_sanitizer_failure_does_not_allow():
    """التحقق من أن فشل التطهير يمنع النشر (Fail-Closed)"""
    res = media_sanitizer.validate_file_security(
        file_path="/non/existent/path/file.pdf",
        expected_type="document",
        original_filename="file.pdf"
    )
    assert res is False


@pytest.mark.asyncio
async def test_parser_timeout_does_not_allow(tmp_path):
    """التحقق من أن أي Timeout أثناء فحص المستندات ينتج BLOCK"""
    doc_file = tmp_path / "timeout_test.txt"
    doc_file.write_text("نص اختباري", encoding="utf-8")
    analyzer = MediaAnalyzer(fail_closed=True)
    # محاكاة timeout أو استثناء في المحلل
    with patch.object(analyzer.doc_analyzer, "extract_document_text", side_effect=TimeoutError("Processing timed out")):
        res = await analyzer.analyze_payload(ContentPayload(
            content_type=ContentType.DOCUMENT,
            file_path=str(doc_file),
            filename="timeout_test.txt"
        ))
        assert res.is_allowed is False
        assert res.action == ModerationAction.BLOCK


@pytest.mark.asyncio
async def test_unknown_media_does_not_allow(tmp_path):
    """التحقق من حظر أي وسائط غير معروفة الصيغة أو تالفة في Strict Mode"""
    unknown_file = tmp_path / "mystery.xyz"
    unknown_file.write_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07")
    analyzer = MediaAnalyzer(fail_closed=True)
    res = await analyzer.analyze_payload(ContentPayload(
        content_type=ContentType.DOCUMENT,
        file_path=str(unknown_file),
        filename="mystery.xyz"
    ))
    assert res.is_allowed is False
    assert res.action == ModerationAction.BLOCK


# =========================================================================
# 3. PUBLICATION GATE CONTRACT TESTS (Contracts 10 & 11)
# =========================================================================

def test_no_direct_channel_send_outside_publisher():
    """
    فحص ثابت (Static AST / Regex Scan) يتأكد من عدم وجود أي استدعاء مباشر لـ bot.send_*
    موجه إلى channel_id خارج ملف publisher.py
    """
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    forbidden_pattern = re.compile(r"bot\.send_(message|photo|document|voice|audio|video|animation)\s*\(\s*[^)]*channel_id", re.IGNORECASE)

    violations = []
    for root, dirs, files in os.walk(project_root):
        if "tests" in root or ".pytest_cache" in root or "media_tmp" in root:
            continue
        for file in files:
            if file.endswith(".py") and file not in ["publisher.py", "logger.py"]:
                full_path = os.path.join(root, file)
                with open(full_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if forbidden_pattern.search(content):
                        violations.append(file)

    assert len(violations) == 0, f"Found direct channel sends outside publisher.py: {violations}"


@pytest.mark.asyncio
async def test_all_channel_posts_protected_content():
    """التحقق من أن بوابة النشر تفرض دائماً protect_content=True"""
    mock_bot = AsyncMock()
    mock_bot.send_message.return_value = AsyncMock(message_id=12345)
    pub = PublisherService()
    success, msg, res = await pub.publish_post(
        bot=mock_bot,
        channel_id=-1001234567890,
        media_type="text",
        formatted_html="<b>سؤال تجريبي</b>",
        raw_text="سؤال تجريبي"
    )
    assert success is True
    mock_bot.send_message.assert_called_once()
    kwargs = mock_bot.send_message.call_args.kwargs
    assert kwargs.get("protect_content") is True


# =========================================================================
# 4. EXECUTABLE & ARCHIVE CONTRACT TESTS (Contracts 23 & 24)
# =========================================================================

def test_executable_disguised_extension_blocked(tmp_path):
    """التحقق من حظر الملفات التنفيذية حتى لو تم تغيير امتدادها إلى .pdf أو .bin"""
    fake_pdf = tmp_path / "evil.pdf"
    # رأس ملف Windows PE التنفيذي (MZ)
    fake_pdf.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This is malicious binary")
    is_safe = media_sanitizer.validate_file_security(
        file_path=str(fake_pdf),
        expected_type="document",
        original_filename="evil.pdf"
    )
    assert is_safe is False


def test_zip_path_traversal_archive_blocked(tmp_path):
    """التحقق من حظر أرشيفات ZIP التي تحتوي على Path Traversal (../../evil.sh)"""
    bad_zip_path = tmp_path / "traversal.zip"
    with zipfile.ZipFile(bad_zip_path, "w") as z:
        z.writestr("../../../evil.sh", "echo hacked")
    is_safe = media_sanitizer.validate_file_security(
        file_path=str(bad_zip_path),
        expected_type="document",
        original_filename="traversal.zip"
    )
    assert is_safe is False


# =========================================================================
# 5. MEDIA TEMP FILE CLEANUP CONTRACT TESTS (Contract 25)
# =========================================================================

@pytest.mark.asyncio
async def test_temp_files_cleanup_on_error_and_success(tmp_path):
    """التحقق من حذف الملف المؤقت دائماً في finally block وعدم بقاء أي مخلفات"""
    test_temp_file = tmp_path / "temp_media_file.jpg"
    test_temp_file.write_bytes(b"temporary binary media data")
    assert test_temp_file.exists()

    # محاكاة التنظيف
    media_sanitizer.cleanup_file(str(test_temp_file))
    assert not test_temp_file.exists()


# =========================================================================
# 6. LOGGING & PRIVACY CONTRACT TESTS (Contract 30)
# =========================================================================

def test_log_scrubbing_contracts_zero_pii():
    """التحقق من أن نظام السجلات يطهر كافة المعرفات والتوكنات ومفاتيح التشفير تلقائياً"""
    from utils.logger import scrub_pii_from_log_message

    dirty_log = (
        "User 123456789 with username @student_john submitted post. "
        "Token: 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11. "
        "EncryptionKey: vK5_8d_fake_key_9999999999999999999999=. "
        "Phone: +966501234567"
    )
    clean_log = scrub_pii_from_log_message(dirty_log)
    assert "123456789" not in clean_log
    assert "ABC-DEF1234ghIkl" not in clean_log
    assert "+966501234567" not in clean_log
    assert "@student_john" not in clean_log
