"""
Failure Mode and Fail-Closed Robustness Test Suite.
Verifies that when any analyzer, parser, or security dependency fails, times out,
or is unavailable, the system strictly fails closed (BLOCK / REVIEW) and never allows publication.
"""
import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock
from PIL import Image

from moderation.media_analyzer import MediaAnalyzer
from moderation.analyzers.ocr_analyzer import OCRAnalyzer
from moderation.analyzers.asr_analyzer import ASRAnalyzer
from moderation.analyzers.visual_analyzer import VisualAnalyzer
from moderation.analyzers.document_analyzer import DocumentAnalyzer
from moderation.analyzers.archive_analyzer import ArchiveAnalyzer
from moderation.models import (
    ContentType,
    ContentPayload,
    ModerationAction,
    ViolationCategory,
    SeverityLevel,
    AnalysisStatus
)
from security.media_sanitizer import MediaSanitizer


@pytest.mark.asyncio
async def test_ocr_unavailable_fail_closed():
    """التحقق من أن عدم توفر أو فشل Tesseract OCR يؤدي إلى الرفض في النمط الصارم"""
    ocr_analyzer = OCRAnalyzer(enable_ocr=True, fail_closed=True)
    img = Image.new("RGB", (100, 100), color="white")

    with patch("pytesseract.image_to_string", side_effect=Exception("Tesseract engine not found")):
        # In ocr_analyzer, an unhandled exception or missing engine produces an error signal or empty text
        pass

    media_analyzer = MediaAnalyzer(fail_closed=True)
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        img.save(f, format="PNG")
        temp_img_path = f.name

    try:
        with patch.object(media_analyzer.ocr_analyzer, "extract_text_from_image", side_effect=Exception("OCR engine crashed")):
            res = await media_analyzer.analyze_media(temp_img_path, "photo")
            assert res.is_allowed is False
            assert res.action == ModerationAction.BLOCK
            assert res.category == ViolationCategory.MEDIA_UNSAFE
    finally:
        if os.path.exists(temp_img_path):
            os.remove(temp_img_path)


@pytest.mark.asyncio
async def test_asr_failure_fail_closed():
    """التحقق من أن فشل أو عدم توفر التعرف على الصوت ASR يؤدي للرفض"""
    media_analyzer = MediaAnalyzer(fail_closed=True)
    with tempfile.NamedTemporaryFile(suffix=".ogg", delete=False) as f:
        f.write(b"OggS\x00\x02" + b"\x00" * 100)
        temp_audio_path = f.name

    try:
        with patch.object(media_analyzer.asr_analyzer, "transcribe_audio", side_effect=Exception("ASR Speech recognition timeout")):
            res = await media_analyzer.analyze_media(temp_audio_path, "voice")
            assert res.is_allowed is False
            assert res.action == ModerationAction.BLOCK
            assert res.category == ViolationCategory.MEDIA_UNSAFE
    finally:
        if os.path.exists(temp_audio_path):
            os.remove(temp_audio_path)


@pytest.mark.asyncio
async def test_visual_analyzer_failure_fail_closed():
    """التحقق من أن فشل المصنف البصري للصور يولد إشارة MEDIA_UNSAFE ويمنع النشر"""
    media_analyzer = MediaAnalyzer(fail_closed=True)
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
        img = Image.new("RGB", (50, 50), color="blue")
        img.save(f, format="JPEG")
        temp_img_path = f.name

    try:
        with patch.object(media_analyzer.visual_analyzer, "analyze_image_safety", side_effect=Exception("Visual classifier OOM")):
            res = await media_analyzer.analyze_media(temp_img_path, "photo")
            assert res.is_allowed is False
            assert res.action == ModerationAction.BLOCK
            assert res.category == ViolationCategory.MEDIA_UNSAFE
    finally:
        if os.path.exists(temp_img_path):
            os.remove(temp_img_path)


@pytest.mark.asyncio
async def test_document_parser_failure_fail_closed():
    """التحقق من أن تلف أو فشل محلل المستندات PDF/DOCX يؤدي إلى الرفض الفوري"""
    media_analyzer = MediaAnalyzer(fail_closed=True)
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(b"%PDF-1.7\nCorrupted binary payload\x00\xff")
        temp_doc_path = f.name

    try:
        with patch.object(media_analyzer.doc_analyzer, "extract_document_text", side_effect=Exception("PDF decode fatal error")):
            res = await media_analyzer.analyze_media(temp_doc_path, "document", original_filename="lecture.pdf")
            assert res.is_allowed is False
            assert res.action == ModerationAction.BLOCK
            assert res.category == ViolationCategory.MEDIA_UNSAFE
    finally:
        if os.path.exists(temp_doc_path):
            os.remove(temp_doc_path)


@pytest.mark.asyncio
async def test_sanitizer_failure_fail_closed():
    """التحقق من أن فشل التطهير أو عدم تطابق البايتات السحرية يمنع النشر تماماً"""
    sanitizer = MediaSanitizer()

    # محاولة تمرير ملف بامتداد غير مدعوم
    with pytest.raises(ValueError):
        sanitizer.sanitize_filename("exploit.sh")

    # محاولة فحص ملف تالف
    is_valid = sanitizer.validate_file_security("non_existent_file.pdf")
    assert is_valid is False


@pytest.mark.asyncio
async def test_unknown_binary_fail_closed():
    """التحقق من أن الملفات الثنائية غير المعروفة أو الامتدادات المبهمة تُرفض فوراً"""
    media_analyzer = MediaAnalyzer(fail_closed=True)
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x00\x01\x02\x03\x04\x05" * 10)
        temp_bin_path = f.name

    try:
        payload = ContentPayload(
            content_type=ContentType.DOCUMENT,
            file_path=temp_bin_path,
            filename="unknown_data.bin",
            size_bytes=os.path.getsize(temp_bin_path)
        )
        res = await media_analyzer.analyze_payload(payload)
        assert res.is_allowed is False
        assert res.action == ModerationAction.BLOCK
        assert res.category == ViolationCategory.MEDIA_UNSAFE
    finally:
        if os.path.exists(temp_bin_path):
            os.remove(temp_bin_path)


@pytest.mark.asyncio
async def test_archive_scanner_failure_fail_closed():
    """التحقق من أن فشل فحص الأرشيف أو تلفه يمنع المحتوى من النشر"""
    media_analyzer = MediaAnalyzer(fail_closed=True)
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        f.write(b"PK\x03\x04\x00\x00CorruptedZipStream")
        temp_zip_path = f.name

    try:
        payload = ContentPayload(
            content_type=ContentType.DOCUMENT,
            file_path=temp_zip_path,
            filename="homework.zip",
            size_bytes=os.path.getsize(temp_zip_path)
        )
        res = await media_analyzer.analyze_payload(payload)
        assert res.is_allowed is False
        assert res.action == ModerationAction.BLOCK
        assert res.category == ViolationCategory.MEDIA_UNSAFE
    finally:
        if os.path.exists(temp_zip_path):
            os.remove(temp_zip_path)
