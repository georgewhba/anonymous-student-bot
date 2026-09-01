"""
Visual Content Safety Analyzer.
Inspects images, video keyframes, GIFs, and stickers for visually explicit or unsafe content
using heuristic skin-tone/color distribution analysis and visual safety classifiers with fail-closed safety.
"""
from typing import Optional
from PIL import Image
from utils.logger import logger
from moderation.models import (
    ViolationCategory,
    SeverityLevel,
    ModerationSignal
)


class VisualAnalyzer:
    """محلل السلامة البصرية للصور وإطارات الفيديو (Visual Safety Classifier)"""

    def __init__(self, fail_closed: bool = True, skin_threshold: float = 0.65):
        self.fail_closed = fail_closed
        self.skin_threshold = skin_threshold

    def analyze_image_safety(self, image_input) -> Optional[ModerationSignal]:
        """
        فحص الصورة بصرياً لاكتشاف المحتوى الإباحي أو العاري الصريح
        يرجع: ModerationSignal إن وجد انتهاك، أو None إن كانت الصورة آمنة
        """
        try:
            if isinstance(image_input, str):
                with Image.open(image_input) as img:
                    return self._inspect_pil_image(img)
            elif isinstance(image_input, Image.Image):
                return self._inspect_pil_image(image_input)
            else:
                return None
        except Exception as e:
            logger.error(f"خطأ أثناء الفحص البصري للصورة: {e}")
            if self.fail_closed:
                return ModerationSignal(
                    source="VISUAL",
                    category=ViolationCategory.MEDIA_UNSAFE,
                    severity=SeverityLevel.MEDIUM,
                    confidence=1.0,
                    is_violation=True,
                    is_security=True,
                    reason=f"Visual classifier decoding failure: {str(e)}"
                )
            return None

    def _inspect_pil_image(self, img: Image.Image) -> Optional[ModerationSignal]:
        """فحص الألوان وتوزيع الصبغات الجلدية (Skin-Tone Heuristics & Visual NSFW Markers)"""
        # 1. تحجيم الصورة لأبعاد صغيرة لتسريع التحليل ومنع استهلاك الذاكرة
        thumb = img.copy()
        thumb.thumbnail((120, 120))
        rgb_img = thumb.convert("RGB")
        width, height = rgb_img.size
        total_pixels = width * height
        if total_pixels == 0:
            return None

        skin_pixels = 0
        raw_bytes = rgb_img.tobytes()

        for i in range(0, len(raw_bytes), 3):
            r, g, b = raw_bytes[i], raw_bytes[i + 1], raw_bytes[i + 2]
            # معايير درجات البشرة الطبيعية في فضاء RGB
            # R > 95, G > 40, B > 20, max(R,G,B) - min(R,G,B) > 15, |R - G| > 15, R > G, R > B
            if (r > 95 and g > 40 and b > 20 and
                (max(r, g, b) - min(r, g, b) > 15) and
                abs(r - g) > 15 and r > g and r > b):
                skin_pixels += 1

        skin_ratio = skin_pixels / total_pixels

        # إذا كانت نسبة درجات الجلد مرتفعة جداً وتتجاوز حد الأمان
        if skin_ratio >= self.skin_threshold:
            return ModerationSignal(
                source="VISUAL",
                category=ViolationCategory.EXPLICIT,
                severity=SeverityLevel.HIGH,
                confidence=min(1.0, 0.70 + (skin_ratio * 0.3)),
                is_violation=True,
                is_security=False,
                reason=f"Excessive explicit visual skin-tone density ({skin_ratio:.1%})"
            )

        return None
