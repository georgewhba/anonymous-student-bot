"""
Media Moderation Tests.
Tests document text extraction, archive protection, image limits, caption inspection, and fail-closed policies.
"""
import os
import zipfile
import pytest
from PIL import Image
from moderation.engine import moderation_engine
from moderation.models import ModerationAction, ViolationCategory


@pytest.mark.asyncio
async def test_txt_document_moderation(tmp_path):
    # 1. مستند نصي نظيف
    clean_txt = tmp_path / "clean_notes.txt"
    clean_txt.write_text("هذه ملاحظات محاضرة الفيزياء عن الديناميكا الحرارية.", encoding="utf-8")

    res_clean = await moderation_engine.inspect_media(
        file_path=str(clean_txt),
        media_type="document",
        original_filename="clean_notes.txt"
    )
    assert res_clean.is_allowed is True

    # 2. مستند نصي يحتوي على شتائم
    bad_txt = tmp_path / "bad_notes.txt"
    bad_txt.write_text("ملاحظات تحتوي على شتائم: شرموطة وسافل.", encoding="utf-8")

    res_bad = await moderation_engine.inspect_media(
        file_path=str(bad_txt),
        media_type="document",
        original_filename="bad_notes.txt"
    )
    assert res_bad.is_allowed is False
    assert res_bad.action == ModerationAction.BLOCK


@pytest.mark.asyncio
async def test_docx_document_moderation(tmp_path):
    # إنشاء ملف docx وهمي يحتوي على word/document.xml
    docx_file = tmp_path / "lecture.docx"
    doc_xml_content = """<?xml version="1.0" encoding="UTF-8"?>
    <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
        <w:body>
            <w:p><w:r><w:t>هذا ملف يحتوي على كلمة شرموطة مسيئة</w:t></w:r></w:p>
        </w:body>
    </w:document>"""

    with zipfile.ZipFile(docx_file, "w") as zf:
        zf.writestr("word/document.xml", doc_xml_content)

    res = await moderation_engine.inspect_media(
        file_path=str(docx_file),
        media_type="document",
        original_filename="lecture.docx"
    )
    assert res.is_allowed is False
    assert res.action == ModerationAction.BLOCK


@pytest.mark.asyncio
async def test_zip_archive_security(tmp_path):
    # 1. أرشيف يحتوي على ملف تنفيذي خبيث .exe
    bad_zip = tmp_path / "malicious.zip"
    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("script.exe", b"binary content")

    res_exe = await moderation_engine.inspect_media(
        file_path=str(bad_zip),
        media_type="document",
        original_filename="project.zip"
    )
    assert res_exe.is_allowed is False
    assert res_exe.category == ViolationCategory.MEDIA_UNSAFE

    # 2. أرشيف يحتوي على محاولة Path Traversal
    traversal_zip = tmp_path / "traversal.zip"
    with zipfile.ZipFile(traversal_zip, "w") as zf:
        zf.writestr("../../../etc/passwd", "root:x:0:0")

    res_trav = await moderation_engine.inspect_media(
        file_path=str(traversal_zip),
        media_type="document",
        original_filename="traversal.zip"
    )
    assert res_trav.is_allowed is False
    assert res_trav.category == ViolationCategory.MEDIA_UNSAFE


@pytest.mark.asyncio
async def test_image_dimension_limits_and_caption(tmp_path):
    # 1. صورة عادية مع كابشن مسيء
    img_path = tmp_path / "photo.jpg"
    img = Image.new("RGB", (300, 300), color=(100, 100, 100))
    img.save(img_path, format="JPEG")

    res_caption = await moderation_engine.inspect_media(
        file_path=str(img_path),
        media_type="photo",
        caption="انظر إلى هذا الـ f*u*c*k"
    )
    assert res_caption.is_allowed is False
    assert res_caption.action == ModerationAction.BLOCK

    # 2. صورة عادية مع كابشن نظيف
    res_clean = await moderation_engine.inspect_media(
        file_path=str(img_path),
        media_type="photo",
        caption="مخطط توضيحي لمادة الكيمياء العضوية"
    )
    assert res_clean.is_allowed is True


@pytest.mark.asyncio
async def test_fail_closed_on_missing_file():
    """التحقق من سياسة الفشل الآمن (Fail-Closed) عند غياب الملف أو تلفه"""
    res = await moderation_engine.inspect_media(
        file_path="non_existent_file_path_12345.pdf",
        media_type="document"
    )
    assert res.is_allowed is False
    assert res.category == ViolationCategory.MEDIA_UNSAFE
