"""
PDF Extraction and Moderation Cache Tests.
"""
import time
import pytest
from moderation.cache import ModerationCache
from moderation.models import ModerationResult, ModerationAction, ViolationCategory, SeverityLevel
from moderation.engine import moderation_engine


@pytest.mark.asyncio
async def test_pdf_extraction_clean_and_prohibited(tmp_path):
    """اختبار استخراج ومعالجة ملفات PDF — السماح بالمحتوى التعليمي"""
    import fitz

    # 1. ملف PDF دراسي
    clean_pdf = tmp_path / "clean_syllabus.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 50), "Computer Science Syllabus: Algorithms and Data Structures 2026.")
    doc.save(str(clean_pdf))
    doc.close()

    res_clean = await moderation_engine.inspect_media(
        file_path=str(clean_pdf),
        media_type="document",
        original_filename="syllabus.pdf"
    )
    assert res_clean.is_allowed is True
    assert res_clean.action == ModerationAction.ALLOW

    # 2. ملف PDF دراسي مع محتوى أكاديمي متنوع
    notes_pdf = tmp_path / "notes.pdf"
    doc_notes = fitz.open()
    page_notes = doc_notes.new_page()
    page_notes.insert_text((50, 50), "Lecture notes on History and Philosophy with historical names.")
    doc_notes.save(str(notes_pdf))
    doc_notes.close()

    res_notes = await moderation_engine.inspect_media(
        file_path=str(notes_pdf),
        media_type="document",
        original_filename="notes.pdf"
    )
    assert res_notes.is_allowed is True
    assert res_notes.action == ModerationAction.ALLOW


def test_moderation_cache_lru_and_ttl():
    """اختبار الذاكرة المؤقتة (LRU Cache) وانتهاء الصلاحية وانعدام PII"""
    cache = ModerationCache(max_size=3, ttl_seconds=1)

    res_allow = ModerationResult(
        is_allowed=True,
        action=ModerationAction.ALLOW,
        category=ViolationCategory.NONE,
        severity=SeverityLevel.LOW,
        confidence=1.0,
        reason_ar=""
    )

    cache.set("text1", res_allow)
    cache.set("text2", res_allow)
    cache.set("text3", res_allow)

    assert cache.get("text1") is not None
    assert cache.size() == 3

    # إضافة عنصر رابع يؤدي إلى إخراج أقدم عنصر غير مستخدم (text2)
    cache.set("text4", res_allow)
    assert cache.size() == 3
    assert cache.get("text2") is None
    assert cache.get("text1") is not None
    assert cache.get("text4") is not None

    # اختبار انتهاء الصلاحية TTL
    time.sleep(1.1)
    assert cache.get("text1") is None
    assert cache.get("text4") is None
    assert cache.size() == 0
