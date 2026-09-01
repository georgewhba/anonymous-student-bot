"""
Fuzzing and Generative Noise Tests.
Tests that the multi-layer normalizer consistently detects banned terms even with random noise,
spacing, punctuation, invisible characters, and repetitions inserted.
"""
import random
from moderation.engine import moderation_engine
from moderation.models import ModerationAction

NOISE_CHARS = [".", "-", "_", "/", "*", " ", "\u200B", "\u200C", "\u200D", "\uFEFF", "َ", "ً", "ُ", "ِ", "ّ"]

BASE_BANNED_WORDS = [
    "شرموطة",
    "قحبة",
    "خول",
    "عرص",
    "fuck",
    "bitch",
    "kosomak"
]


def inject_noise(word: str, seed: int) -> str:
    """حقن ضوضاء عشوائية بين أحرف الكلمة"""
    rng = random.Random(seed)
    res = []
    for char in word:
        # تكرار اختياري للحرف
        repeat_count = rng.choice([1, 1, 2, 3])
        res.append(char * repeat_count)
        # إدراج رمز عشوائي أو مسافة
        if rng.random() > 0.4:
            noise = rng.choice(NOISE_CHARS)
            res.append(noise)
    return "".join(res)


def test_generative_fuzzing_noise_resilience():
    """توليد 50 تركيبة عشوائية من الضوضاء والتأكد من نجاح المحرك في حجبها جميعاً"""
    for word in BASE_BANNED_WORDS:
        for seed in range(10):
            fuzzed = inject_noise(word, seed)
            res = moderation_engine.inspect_content(fuzzed)
            assert res.is_allowed is False, (
                f"فشل كشف الكلمة المشوشة بالضوضاء: '{fuzzed}' (الأصل: '{word}')"
            )
            assert res.action == ModerationAction.BLOCK
