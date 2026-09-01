"""
Privacy-Preserving Bounded Moderation Cache.
Uses SHA-256 content hashes, strict TTL expiration, LRU eviction, and zero storage of PII or Telegram IDs.
"""
import time
import hashlib
from typing import Optional, Dict, Tuple
from moderation.models import ModerationResult


class ModerationCache:
    """ذاكرة تخزين مؤقتة آمنة ومحدودة الحجم لنتائج الفحص الرقابي وفق مبدأ LRU"""

    def __init__(self, max_size: int = 2000, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Tuple[float, ModerationResult]] = {}

    @staticmethod
    def _compute_key(text: str) -> str:
        """توليد مفتاح تجزئة آمن للمحتوى فقط دون أي معرفات شخصية"""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def get(self, text: str) -> Optional[ModerationResult]:
        """استرجاع نتيجة الفحص وتحديث وقت الوصول (LRU) إن كانت سارية"""
        if not text:
            return None
        key = self._compute_key(text)
        entry = self._cache.get(key)
        if not entry:
            return None

        timestamp, result = entry
        if time.time() - timestamp > self.ttl_seconds:
            self._cache.pop(key, None)
            return None

        # تحديث وقت الوصول لدعم LRU
        self._cache[key] = (time.time(), result)
        return result

    def set(self, text: str, result: ModerationResult) -> None:
        """حفظ نتيجة الفحص في الذاكرة المؤقتة مع إخراج أقدم العناصر غير المستخدمة (LRU)"""
        if not text:
            return

        key = self._compute_key(text)
        # إذا كان المفتاح موجوداً بالفعل نقوم بتحديثه
        if key in self._cache:
            self._cache[key] = (time.time(), result)
            return

        # تنظيف العناصر منتهية الصلاحية أولاً
        self._evict_expired()

        # إذا ما زالت السعة ممتلئة، نخرج أقدم عنصر (LRU)
        if len(self._cache) >= self.max_size:
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][0], default=None)
            if oldest_key:
                self._cache.pop(oldest_key, None)

        self._cache[key] = (time.time(), result)

    def _evict_expired(self) -> None:
        """إزالة كل العناصر منتهية الصلاحية"""
        now = time.time()
        expired = [k for k, (t, _) in self._cache.items() if now - t > self.ttl_seconds]
        for k in expired:
            self._cache.pop(k, None)

    def size(self) -> int:
        """عدد العناصر السارية المتبقية في الذاكرة"""
        self._evict_expired()
        return len(self._cache)

    def clear(self) -> None:
        self._cache.clear()


moderation_cache = ModerationCache()
