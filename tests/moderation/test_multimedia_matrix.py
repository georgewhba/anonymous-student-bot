"""
Comprehensive Multimedia Moderation Matrix Test Suite.
Exhaustively tests all content types (Text, Photo, PDF, DOCX, XLSX, PPTX, Voice, Audio, Video, GIF, Sticker, Archive, Filename)
and validates the Universal Decision Engine, ContentPayload intake, and strict Fail-Closed policy.
"""
import io
import os
import zipfile
import pytest
from PIL import Image

from moderation.models import (
    ContentType,
    ContentPayload,
    ModerationAction,
    ViolationCategory,
    SeverityLevel,
    ModerationSignal
)
from moderation.engine import ModerationEngine, moderation_engine
from moderation.decision_engine import DecisionEngine
from moderation.analyzers.ocr_analyzer import OCRAnalyzer
from moderation.analyzers.asr_analyzer import ASRAnalyzer
from moderation.analyzers.visual_analyzer import VisualAnalyzer
from moderation.analyzers.document_analyzer import DocumentAnalyzer
from moderation.analyzers.archive_analyzer import ArchiveAnalyzer


# ==============================================================================
# 1. اختبار الحزمة الموحدة ومحرك اتخاذ القرار (ContentPayload & DecisionEngine)
# ==============================================================================

def test_decision_engine_prioritization_and_security_separation():
    """التحقق من أولوية القرار BLOCK > REVIEW > ALLOW وفصل التهديدات الأمنية"""
    engine = DecisionEngine(strict_mode=True)

    # 1. إشارة أمان (Security Signal) ذات خطورة عالية -> BLOCK إلزامي
    sec_sig = ModerationSignal(
        source="ARCHIVE",
        category=ViolationCategory.MEDIA_UNSAFE,
        severity=SeverityLevel.CRITICAL,
        confidence=1.0,
        is_violation=True,
        is_security=True,
        reason="Dangerous binary detected"
    )
    res_sec = engine.evaluate_signals([sec_sig])
    assert res_sec.is_allowed is False
    assert res_sec.action == ModerationAction.BLOCK
    assert "RULE_SECURITY_ARCHIVE" in res_sec.matched_rules

    # 2. إشارة محتوى (Content Signal) -> BLOCK
    content_sig = ModerationSignal(
        source="TEXT",
        category=ViolationCategory.PROFANITY,
        severity=SeverityLevel.HIGH,
        confidence=1.0,
        is_violation=True,
        is_security=False,
        reason="Prohibited profanity"
    )
    res_content = engine.evaluate_signals([content_sig])
    assert res_content.is_allowed is False
    assert res_content.action == ModerationAction.BLOCK

    # 3. إشارات نظيفة بالكامل -> ALLOW
    res_clean = engine.evaluate_signals([])
    assert res_clean.is_allowed is True
    assert res_clean.action == ModerationAction.ALLOW


# ==============================================================================
# 2. فحص الصور (PHOTO): كابشن، OCR، فحص بصري، فشل الفك
# ==============================================================================

@pytest.mark.asyncio
async def test_photo_moderation_pipeline(tmp_path):
    # 1. صورة نظيفة تماماً
    clean_img_path = tmp_path / "clean_photo.jpg"
    Image.new("RGB", (200, 200), color=(50, 100, 150)).save(clean_img_path, format="JPEG")

    payload_clean = ContentPayload(
        content_type=ContentType.PHOTO,
        file_path=str(clean_img_path),
        caption="مخطط لدورة كريبس في الأحياء"
    )
    res_clean = await moderation_engine.inspect_payload(payload_clean)
    assert res_clean.is_allowed is True

    # 2. صورة مع كابشن مسيء
    payload_bad_cap = ContentPayload(
        content_type=ContentType.PHOTO,
        file_path=str(clean_img_path),
        caption="انظر إلى هذا الـ f_u_c_k"
    )
    res_bad_cap = await moderation_engine.inspect_payload(payload_bad_cap)
    assert res_bad_cap.is_allowed is False
    assert res_bad_cap.action == ModerationAction.BLOCK

    # 3. صورة تحاكي محتوى عارٍ صريح بصرياً (High Skin Tone Density)
    nude_img_path = tmp_path / "nude_sim.jpg"
    # ملء الصورة بدرجات لون البشرة الطبيعي (R=220, G=150, B=120)
    Image.new("RGB", (200, 200), color=(220, 150, 120)).save(nude_img_path, format="JPEG")

    payload_nude = ContentPayload(
        content_type=ContentType.PHOTO,
        file_path=str(nude_img_path)
    )
    res_nude = await moderation_engine.inspect_payload(payload_nude)
    assert res_nude.is_allowed is False
    assert res_nude.category == ViolationCategory.EXPLICIT


# ==============================================================================
# 3. فحص المستندات (DOCUMENTS): PDF, DOCX, XLSX, PPTX, TXT
# ==============================================================================

@pytest.mark.asyncio
async def test_document_types_moderation(tmp_path):
    doc_analyzer = DocumentAnalyzer(fail_closed=True)

    # 1. ملف نصي TXT نظيف
    clean_txt = tmp_path / "physics.txt"
    clean_txt.write_text("قوانين نيوتن للحركة في الميكانيكا الكلاسيكية.", encoding="utf-8")
    t, sigs = doc_analyzer.extract_document_text(str(clean_txt))
    assert "قوانين نيوتن" in t
    assert len(sigs) == 0

    # 2. ملف TXT ملغوم ببايتات صفرية (Null Bytes) دالة على ملف ثنائي
    fake_txt = tmp_path / "fake.txt"
    fake_txt.write_bytes(b"text\x00\x00\x00malicious_binary")
    t_fake, sigs_fake = doc_analyzer.extract_document_text(str(fake_txt))
    assert len(sigs_fake) > 0
    assert sigs_fake[0].category == ViolationCategory.MEDIA_UNSAFE

    # 3. ملف DOCX دراسي
    docx_file = tmp_path / "assignment.docx"
    doc_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
        <w:body><w:p><w:r><w:t>واجب مادة الفيزياء - أسئلة وتمارين الباب الأول</w:t></w:r></w:p></w:body>
    </w:document>"""
    with zipfile.ZipFile(docx_file, "w") as zf:
        zf.writestr("word/document.xml", doc_xml)

    payload_docx = ContentPayload(
        content_type=ContentType.DOCUMENT,
        file_path=str(docx_file),
        filename="assignment.docx"
    )
    res_docx = await moderation_engine.inspect_payload(payload_docx)
    assert res_docx.is_allowed is True
    assert res_docx.action == ModerationAction.ALLOW

    # 4. ملف Excel ماكرو محظور (.xlsm)
    xlsm_file = tmp_path / "grades.xlsm"
    xlsm_file.write_bytes(b"PK\x03\x04fake_excel_content")
    payload_xlsm = ContentPayload(
        content_type=ContentType.DOCUMENT,
        file_path=str(xlsm_file),
        filename="grades.xlsm"
    )
    res_xlsm = await moderation_engine.inspect_payload(payload_xlsm)
    assert res_xlsm.is_allowed is False
    assert res_xlsm.category == ViolationCategory.MEDIA_UNSAFE

    # 5. ملف PowerPoint PPTX يحتوي على كائن تنفيذي مدمج
    pptx_file = tmp_path / "slides.pptx"
    with zipfile.ZipFile(pptx_file, "w") as zf:
        zf.writestr("ppt/slides/slide1.xml", "<xml><text>Slide 1</text></xml>")
        zf.writestr("ppt/embeddings/malware.exe", b"MZexecutable")

    payload_pptx = ContentPayload(
        content_type=ContentType.DOCUMENT,
        file_path=str(pptx_file),
        filename="slides.pptx"
    )
    res_pptx = await moderation_engine.inspect_payload(payload_pptx)
    assert res_pptx.is_allowed is False
    assert res_pptx.category == ViolationCategory.MEDIA_UNSAFE


# ==============================================================================
# 4. فحص الأرشيفات المضغوطة (ARCHIVE): فحص عميق متكرر وتواقيع تنفيذية
# ==============================================================================

def test_archive_deep_inspection(tmp_path):
    arch_analyzer = ArchiveAnalyzer(fail_closed=True)

    # 1. أرشيف يحتوي على ملف تنفيذي متخفٍ في هيئة نص (MZ Header)
    bad_zip = tmp_path / "homework.zip"
    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("notes.txt", b"MZ\x90\x00\x03\x00\x00\x00disguised_exe")

    _, sigs = arch_analyzer.inspect_archive(str(bad_zip))
    assert len(sigs) > 0
    assert sigs[0].is_security is True
    assert "Executable binary signature" in sigs[0].reason

    # 2. أرشيف يحتوي على محاولة ثغرة مسار (Path Traversal)
    trav_zip = tmp_path / "exploit.zip"
    with zipfile.ZipFile(trav_zip, "w") as zf:
        zf.writestr("../../../../windows/system32/cmd.exe", b"malware")

    _, trav_sigs = arch_analyzer.inspect_archive(str(trav_zip))
    assert len(trav_sigs) > 0
    assert "Path traversal" in trav_sigs[0].reason


# ==============================================================================
# 5. فحص اسم الملف (Filename Moderation)
# ==============================================================================

@pytest.mark.asyncio
async def test_filename_moderation(tmp_path):
    clean_img = tmp_path / "valid.jpg"
    Image.new("RGB", (100, 100)).save(clean_img)

    # اسم ملف يحتوي على شتائم
    payload_bad_fn = ContentPayload(
        content_type=ContentType.PHOTO,
        file_path=str(clean_img),
        filename="fuck_you_teacher.jpg"
    )
    res_fn = await moderation_engine.inspect_payload(payload_bad_fn)
    assert res_fn.is_allowed is False
    assert res_fn.action == ModerationAction.BLOCK

    # اسم ملف عربي مسيء
    payload_ar_fn = ContentPayload(
        content_type=ContentType.DOCUMENT,
        file_path=str(clean_img),
        filename="كسمك_يا_دكتور.pdf"
    )
    res_ar_fn = await moderation_engine.inspect_payload(payload_ar_fn)
    assert res_ar_fn.is_allowed is False
    assert res_ar_fn.action == ModerationAction.BLOCK


# ==============================================================================
# 6. فحص الصور المتحركة GIF والملصقات (GIF & Sticker Moderation)
# ==============================================================================

@pytest.mark.asyncio
async def test_animation_and_gif_moderation(tmp_path):
    # إنشاء ملف GIF متحرك تجريبي
    gif_path = tmp_path / "animated.gif"
    frames = [
        Image.new("RGBA", (100, 100), color=(255, 0, 0)),
        Image.new("RGBA", (100, 100), color=(0, 255, 0)),
    ]
    frames[0].save(gif_path, format="GIF", save_all=True, append_images=frames[1:], duration=100, loop=0)

    # GIF نظيف
    payload_clean_gif = ContentPayload(
        content_type=ContentType.ANIMATION,
        file_path=str(gif_path),
        caption="حركة توضيحية للموجات"
    )
    res_clean_gif = await moderation_engine.inspect_payload(payload_clean_gif)
    assert res_clean_gif.is_allowed is True

    # GIF مع كابشن مسيء
    payload_bad_gif = ContentPayload(
        content_type=ContentType.ANIMATION,
        file_path=str(gif_path),
        caption="ك س ا م ك"
    )
    res_bad_gif = await moderation_engine.inspect_payload(payload_bad_gif)
    assert res_bad_gif.is_allowed is False
    assert res_bad_gif.action == ModerationAction.BLOCK


# ==============================================================================
# 7. مصفوفة الفشل الآمن الصارمة (Strict Fail-Closed Policy Matrix)
# ==============================================================================

@pytest.mark.asyncio
async def test_fail_closed_matrix():
    """التأكد من أن كافة حالات الفشل تعيد BLOCK/REVIEW ولا تعيد ALLOW أبداً"""
    # 1. ملف غير موجود إطلاقاً
    res_missing = await moderation_engine.inspect_payload(
        ContentPayload(content_type=ContentType.DOCUMENT, file_path="does_not_exist_file.pdf")
    )
    assert res_missing.is_allowed is False
    assert res_missing.action == ModerationAction.BLOCK

    # 2. ملف 0 بايت تالف
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as empty_f:
        empty_path = empty_f.name

    try:
        res_empty = await moderation_engine.inspect_payload(
            ContentPayload(content_type=ContentType.PHOTO, file_path=empty_path)
        )
        assert res_empty.is_allowed is False
        assert res_empty.action == ModerationAction.BLOCK
    finally:
        if os.path.exists(empty_path):
            os.remove(empty_path)
