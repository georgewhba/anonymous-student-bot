"""
Compound Abusive Phrases and Multi-Word Formulas Dictionary.
Covers targeted harassment, sexual harassment formulas, curses, and direct threat expressions.
"""
from typing import List, Dict, Any
from moderation.models import ViolationCategory, SeverityLevel

ABUSIVE_PHRASES: List[Dict[str, Any]] = [
    # Explicit & Sexual Phrases
    {"phrase": "ابن الشرموطة", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL},
    {"phrase": "ابن الشرموطه", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL},
    {"phrase": "ابن العاهرة", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL},
    {"phrase": "ابن العاهره", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL},
    {"phrase": "كس اختك", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL},
    {"phrase": "كس امك", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL},
    {"phrase": "كسامك", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL},
    {"phrase": "كسمك", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL},
    {"phrase": "كس خالتك", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL},
    {"phrase": "يا عرص", "cat": ViolationCategory.SEXUAL, "sev": SeverityLevel.HIGH},
    {"phrase": "يا معرص", "cat": ViolationCategory.SEXUAL, "sev": SeverityLevel.HIGH},
    {"phrase": "تعالي خاص", "cat": ViolationCategory.HARASSMENT, "sev": SeverityLevel.MEDIUM},
    {"phrase": "ابعتي صورك", "cat": ViolationCategory.HARASSMENT, "sev": SeverityLevel.HIGH},
    {"phrase": "send nudes", "cat": ViolationCategory.HARASSMENT, "sev": SeverityLevel.HIGH},
    {"phrase": "send me nudes", "cat": ViolationCategory.HARASSMENT, "sev": SeverityLevel.HIGH},

    # Profanity & Insults
    {"phrase": "ابن الكلب", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL},
    {"phrase": "ابن الحرام", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL},
    {"phrase": "ابن المره", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH},
    {"phrase": "ابن الوسخة", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH},
    {"phrase": "ابن الوسخه", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH},
    {"phrase": "يلعن ابوك", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL},
    {"phrase": "يلعن امك", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL},
    {"phrase": "يلعن اهلك", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL},
    {"phrase": "يا خول", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH},
    {"phrase": "يا وسخ", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.MEDIUM},
    {"phrase": "يا حقير", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.MEDIUM},
    {"phrase": "يا سافل", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.MEDIUM},
    {"phrase": "يا حيوان", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.MEDIUM},
    {"phrase": "يا حمار", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.MEDIUM},
    {"phrase": "يا واطي", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.MEDIUM},
    {"phrase": "fuck you", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL},
    {"phrase": "fuck off", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL},
    {"phrase": "fk you", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL},
    {"phrase": "fuk you", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL},
    {"phrase": "fuk u", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL},
    {"phrase": "fc u", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL},
    {"phrase": "shut up", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.LOW},
    {"phrase": "son of a bitch", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL},
    {"phrase": "piece of shit", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH},

    # Hate Speech & Religious Desecration
    {"phrase": "يلعن دينك", "cat": ViolationCategory.HATE, "sev": SeverityLevel.CRITICAL},
    {"phrase": "يلعن دين", "cat": ViolationCategory.HATE, "sev": SeverityLevel.CRITICAL},
    {"phrase": "يلعن ربك", "cat": ViolationCategory.HATE, "sev": SeverityLevel.CRITICAL},
    {"phrase": "يا كافر", "cat": ViolationCategory.HATE, "sev": SeverityLevel.HIGH},

    # Direct Threats
    {"phrase": "هقتلك يا", "cat": ViolationCategory.THREAT, "sev": SeverityLevel.CRITICAL},
    {"phrase": "هدبحك يا", "cat": ViolationCategory.THREAT, "sev": SeverityLevel.CRITICAL},
    {"phrase": "هولع فيك", "cat": ViolationCategory.THREAT, "sev": SeverityLevel.CRITICAL},
    {"phrase": "i will kill you", "cat": ViolationCategory.THREAT, "sev": SeverityLevel.CRITICAL},
    {"phrase": "i'm going to kill you", "cat": ViolationCategory.THREAT, "sev": SeverityLevel.CRITICAL},
    {"phrase": "i will hunt you down", "cat": ViolationCategory.THREAT, "sev": SeverityLevel.CRITICAL},
]
