"""
Bounded Fuzzy Matching and Similarity Engine.
Enforces length-dependent thresholds, Damerau-Levenshtein transposition checks,
and strict safeguards against CPU exhaustion and ReDoS attacks.
"""
from typing import Tuple, Optional


def bounded_levenshtein(s1: str, s2: str, max_dist: int = 2) -> int:
    """
    حساب مسافة ليفنشتاين مع مراعاة تبديل الأحرف المتجاورة (Damerau-Levenshtein)
    بحد أقصى max_dist لتسريع الفحص وتجنب استنزاف المعالج.
    """
    if s1 == s2:
        return 0
    len1, len2 = len(s1), len(s2)
    if abs(len1 - len2) > max_dist:
        return max_dist + 1
    if len1 > 60 or len2 > 60:
        return max_dist + 1

    # مصفوفة المسافات الكاملة بحجم صغير ومحدد
    d = [[0] * (len2 + 1) for _ in range(len1 + 1)]

    for i in range(len1 + 1):
        d[i][0] = i
    for j in range(len2 + 1):
        d[0][j] = j

    for i in range(1, len1 + 1):
        min_in_row = d[i][0]
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,       # حذف
                d[i][j - 1] + 1,       # إضافة
                d[i - 1][j - 1] + cost  # استبدال
            )
            # فحص تبديل الأحرف المتجاورة (Transposition / Damerau)
            if i > 1 and j > 1 and s1[i - 1] == s2[j - 2] and s1[i - 2] == s2[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)

            if d[i][j] < min_in_row:
                min_in_row = d[i][j]

        # قطع مبكر إذا تجاوز أقل مسافة في الصف الحد المسموح
        if min_in_row > max_dist:
            return max_dist + 1

    return d[len1][len2]


def normalized_similarity(s1: str, s2: str) -> float:
    """حساب نسبة التشابه المعيارية بين سلسلتين (من 0.0 إلى 1.0)"""
    if not s1 or not s2:
        return 0.0
    if s1 == s2:
        return 1.0

    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0

    dist = bounded_levenshtein(s1, s2, max_dist=max(3, max_len // 3))
    return max(0.0, 1.0 - (dist / max_len))


def is_fuzzy_match(
    token: str,
    target: str,
    custom_threshold: Optional[float] = None
) -> Tuple[bool, float]:
    """
    فحص التطابق الضبابي الذكي المعتمد على طول الكلمة لمنع الإيجابيات الكاذبة (False Positives)
    """
    if not token or not target:
        return False, 0.0

    t_len = len(target)
    tok_len = len(token)

    # 1. الكلمات القصيرة جداً (< 4 أحرف) تتطلب تطابقاً تاماً فقط
    if t_len < 4 or tok_len < 4:
        if token == target:
            return True, 1.0
        return False, 0.0

    # 2. الكلمات متوسطة الطول (4 - 6 أحرف): تتطلب تشابه >= 0.80 أو تبديل أحرف متجاورة (Transposition)
    if 4 <= t_len <= 6:
        max_d = 1
        dist = bounded_levenshtein(token, target, max_dist=max_d)
        if dist <= max_d:
            sim = 1.0 - (dist / max(tok_len, t_len))
            threshold = custom_threshold or 0.80
            if sim >= threshold or (sorted(token) == sorted(target) and dist <= 1):
                return True, sim
        return False, 0.0

    # 3. الكلمات الطويلة (> 6 أحرف): مسافة تعديل قصوى 2 أو نسبة تشابه >= 0.75
    max_d = 2
    dist = bounded_levenshtein(token, target, max_dist=max_d)
    if dist <= max_d:
        sim = 1.0 - (dist / max(tok_len, t_len))
        threshold = custom_threshold or 0.75
        if sim >= threshold:
            return True, sim

    return False, 0.0
