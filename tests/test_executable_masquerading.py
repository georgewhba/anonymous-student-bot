"""
Executable Masquerading & Malicious File Test Suite.
Verifies deep magic byte checking, PE/ELF/Mach-O/Script rejection,
and protection against disguised malware extensions.
"""
import io
import zipfile
import pytest
from security.media_sanitizer import MediaSanitizer
from moderation.media_analyzer import MediaAnalyzer


@pytest.fixture
def sanitizer():
    return MediaSanitizer()


@pytest.fixture
def analyzer():
    return MediaAnalyzer()


def test_dangerous_extension_rejection(sanitizer):
    """التحقق من رفض الامتدادات التنفيذية والبرمجية دون استبدالها بصيغ مبهمة"""
    dangerous_names = [
        "malware.exe", "script.sh", "payload.bat", "trojan.dll",
        "botnet.py", "exploit.vbs", "app.apk", "virus.elf", "dropper.bin"
    ]
    for d_name in dangerous_names:
        with pytest.raises(ValueError) as exc:
            sanitizer.sanitize_filename(d_name)
        assert "محظور أمنياً" in str(exc.value)


def test_executable_magic_bytes_rejection(sanitizer):
    """التحقق من رفض البايتات السحرية للتنفيذيات حتى لو كان الامتداد مصرحاً به"""
    # ملف PE تنفيذي (MZ) تم تمويهه كامتداد pdf
    pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    assert sanitizer.validate_magic_bytes(pe_header, ".pdf") is False
    assert sanitizer.validate_magic_bytes(pe_header, ".docx") is False
    assert sanitizer.validate_magic_bytes(pe_header, ".jpg") is False

    # ملف Linux ELF تنفيذي تم تمويهه كامتداد png
    elf_header = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    assert sanitizer.validate_magic_bytes(elf_header, ".png") is False

    # شل سكريبت تم تمويهه كامتداد txt
    script_header = b"#!/bin/bash\nrm -rf /"
    assert sanitizer.validate_magic_bytes(script_header, ".txt") is False

    # ملف Java Classfile
    java_header = b"\xca\xfe\xba\xbe\x00\x00\x00\x34"
    assert sanitizer.validate_magic_bytes(java_header, ".pdf") is False


def test_valid_magic_bytes_allow(sanitizer):
    """التحقق من قبول الملفات المطابقة لبايتاتها السحرية الحقيقية"""
    pdf_header = b"%PDF-1.7\r\n1 0 obj"
    assert sanitizer.validate_magic_bytes(pdf_header, ".pdf") is True

    jpg_header = b"\xff\xd8\xff\xe0\x00\x10JFIF"
    assert sanitizer.validate_magic_bytes(jpg_header, ".jpg") is True

    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    assert sanitizer.validate_magic_bytes(png_header, ".png") is True

    docx_header = b"PK\x03\x04\x14\x00\x06\x00"
    assert sanitizer.validate_magic_bytes(docx_header, ".docx") is True


def test_zip_archive_disguised_executable_detection(analyzer, tmp_path):
    """التحقق من كشف الملفات التنفيذية المموهة داخل أرشيف الـ ZIP"""
    zip_file_path = tmp_path / "malicious_archive.zip"

    # إنشاء أرشيف يحتوي على ملف تنفيذي مموه باسم صورة
    with zipfile.ZipFile(str(zip_file_path), "w") as zf:
        # ملف MZ مقنع باسم image.png داخل الأرشيف
        zf.writestr("assignment/image.png", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00")
        zf.writestr("assignment/notes.txt", "ملاحظات عادية".encode("utf-8"))

    res = analyzer._inspect_zip_archive(str(zip_file_path))
    assert res.is_allowed is False
    assert "مموه" in res.reason_ar or "محظور" in res.reason_ar


def test_zip_path_traversal_rejection(analyzer, tmp_path):
    """التحقق من رفض محاولات Path Traversal داخل أرشيف ZIP"""
    zip_file_path = tmp_path / "traversal.zip"
    with zipfile.ZipFile(str(zip_file_path), "w") as zf:
        zf.writestr("../../etc/passwd", b"root:x:0:0:")

    res = analyzer._inspect_zip_archive(str(zip_file_path))
    assert res.is_allowed is False
    assert "غير آمنة" in res.reason_ar or "Path traversal" in res.reasons[0]
