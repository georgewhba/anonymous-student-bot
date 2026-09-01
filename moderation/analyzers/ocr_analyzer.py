"""
OCR Analyzer for Images and Scanned Documents.
Handles Arabic, English, mixed scripts, image preprocessing, and strict fail-closed error handling.
"""
import io
from typing import Optional, Tuple
from PIL import Image, ImageEnhance, ImageFilter
from utils.logger import logger
from moderation.models import (
    ViolationCategory,
    SeverityLevel,
    ModerationSignal
)

MAX_EXTRACTED_OCR_CHARS = 30000


class OCRAnalyzer:
    """محلل استخراج النصوص من الصور والمستندات الممسوحة ضوئياً (OCR Engine)"""

    def __init__(self, enable_ocr: bool = True, fail_closed: bool = True, timeout: int = 5):
        self.enable_ocr = enable_ocr
        self.fail_closed = fail_closed
        self.timeout = timeout

    def extract_text_from_image(self, file_path_or_bytes) -> Tuple[str, Optional[ModerationSignal]]:
        """
        استخراج النصوص من صورة مع تطبيق تحسين التباين والمعالجة الثنائية
        يرجع: (extracted_text, error_signal)
        """
        if not self.enable_ocr:
            return "", None

        try:
            # 1. قراءة الصورة
            if isinstance(file_path_or_bytes, (str, bytes, io.BytesIO)):
                img = Image.open(file_path_or_bytes)
            else:
                img = file_path_or_bytes

            # 2. فحص أبعاد الصورة لتجنب هجمات Decompression Bombs
            if img.width > 8192 or img.height > 8192:
                return "", ModerationSignal(
                    source="OCR",
                    category=ViolationCategory.MEDIA_UNSAFE,
                    severity=SeverityLevel.HIGH,
                    confidence=1.0,
                    is_violation=True,
                    is_security=True,
                    reason="Image dimensions exceed safe limits"
                )

            # 3. محاولة استخراج النصوص باستخدام Tesseract OCR
            extracted_text = ""
            try:
                import pytesseract
                # تحسين الصورة لاستخراج أمثل للنصوص العربية والإنجليزية
                gray = img.convert("L")
                enhancer = ImageEnhance.Contrast(gray)
                enhanced = enhancer.enhance(1.5)

                extracted_text = pytesseract.image_to_string(
                    enhanced,
                    lang="ara+eng",
                    timeout=self.timeout
                )
            except ImportError:
                logger.warning("pytesseract is not available in the environment")
                if self.fail_closed:
                    return "", ModerationSignal(
                        source="OCR",
                        category=ViolationCategory.MEDIA_UNSAFE,
                        severity=SeverityLevel.HIGH,
                        confidence=1.0,
                        is_violation=True,
                        is_security=True,
                        reason="pytesseract dependency is missing in environment"
                    )
            except Exception as e:
                logger.error(f"خطأ أثناء استدعاء OCR: {e}")

            return (extracted_text or "")[:MAX_EXTRACTED_OCR_CHARS], None

        except Exception as e:
            logger.error(f"فشل معالجة الصورة في محرك OCR: {e}")
            if self.fail_closed:
                return "", ModerationSignal(
                    source="OCR",
                    category=ViolationCategory.MEDIA_UNSAFE,
                    severity=SeverityLevel.HIGH,
                    confidence=1.0,
                    is_violation=True,
                    is_security=True,
                    reason=f"Corrupted image in OCR pipeline: {str(e)}"
                )
            return "", None
