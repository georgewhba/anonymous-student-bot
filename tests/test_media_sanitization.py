"""
Media Sanitization and Processing Tests.
Tests EXIF/GPS stripping, filename sanitization, magic bytes validation, and decompression bomb protection.
"""
import io
import pytest
from PIL import Image
from security.media_sanitizer import MediaSanitizer, DANGEROUS_EXTENSIONS


def test_photo_exif_and_metadata_stripping():
    sanitizer = MediaSanitizer()

    # إنشاء صورة JPEG تجريبية
    img = Image.new("RGB", (200, 200), color=(255, 0, 0))
    raw_output = io.BytesIO()
    # حفظ الصورة
    img.save(raw_output, format="JPEG")
    raw_bytes = raw_output.getvalue()

    # تطهير الصورة
    clean_bytes = sanitizer.sanitize_image_bytes(raw_bytes)
    assert len(clean_bytes) > 0

    # فتح الصورة المطهرة والتحقق من سلامتها وخلوها من EXIF
    with Image.open(io.BytesIO(clean_bytes)) as clean_img:
        assert clean_img.size == (200, 200)
        assert clean_img.format in ("JPEG", "PNG")
        exif = clean_img.getexif()
        assert len(exif) == 0


def test_filename_sanitization_and_path_traversal():
    sanitizer = MediaSanitizer()

    # 1. محاولة Path Traversal مع امتداد مصرح
    raw1 = "../../../../etc/passwd.pdf"
    clean1 = sanitizer.sanitize_filename(raw1)
    assert ".." not in clean1
    assert "/" not in clean1
    assert "\\" not in clean1
    assert clean1 == "passwd.pdf"

    # 2. ملف ذو امتداد تنفيذي خطير - يرفض بإلقاء ValueError
    raw2 = "malicious_script.exe"
    with pytest.raises(ValueError) as exc2:
        sanitizer.sanitize_filename(raw2)
    assert "محظور أمنياً" in str(exc2.value)

    raw3 = "hack.bat"
    with pytest.raises(ValueError) as exc3:
        sanitizer.sanitize_filename(raw3)
    assert "محظور أمنياً" in str(exc3.value)

    # 3. ملف طبيعي آمن
    raw4 = "محاضرة_الخوارزميات_رقم_1.pdf"
    clean4 = sanitizer.sanitize_filename(raw4)
    assert clean4.endswith(".pdf")
    assert "محاضرة_الخوارزميات" in clean4


def test_magic_bytes_validation():
    sanitizer = MediaSanitizer()

    # بايتات PDF صحيحة
    pdf_bytes = b"%PDF-1.7 ..."
    assert sanitizer.validate_magic_bytes(pdf_bytes, ".pdf") is True

    # محاولة تزييف امتداد (ملف تنفيذي MZ متنكر في هيئة PDF)
    fake_pdf = b"MZ\x90\x00\x03\x00\x00\x00"
    assert sanitizer.validate_magic_bytes(fake_pdf, ".pdf") is False

    # بايتات PNG صحيحة
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00"
    assert sanitizer.validate_magic_bytes(png_bytes, ".png") is True

    # بايتات JPEG صحيحة
    jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10"
    assert sanitizer.validate_magic_bytes(jpeg_bytes, ".jpg") is True


def test_decompression_bomb_protection():
    sanitizer = MediaSanitizer()

    # محاكاة صورة ضخمة جداً تتجاوز الحد الأقصى (8192px)
    huge_img = Image.new("RGB", (9000, 9000), color=(0, 255, 0))
    buf = io.BytesIO()
    huge_img.save(buf, format="JPEG")
    huge_bytes = buf.getvalue()

    with pytest.raises(ValueError, match="أبعاد الصورة"):
        sanitizer.sanitize_image_bytes(huge_bytes)
