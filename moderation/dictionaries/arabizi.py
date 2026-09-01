"""
Arabizi / Franco-Arabic Categorized Vocabulary Dictionary.
Covers Latin-scripted Arabic profanity, explicit terms, insults, and harassment.
"""
from typing import List, Dict, Any
from moderation.models import ViolationCategory, SeverityLevel

ARABIZI_TERMS: List[Dict[str, Any]] = [
    # Explicit & Sexual
    {"term": "kosomak", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "ksomak", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "kosom", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "ksom", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "ksmk", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "kcmk", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "kos5tk", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "sharmota", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "sharmouta", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "sharmoota", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "sharameet", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "shrmta", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "shrm6a", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "7a2ba", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "2a7ba", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "manyook", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "manyk", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "manyak", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "mnayek", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "mnayak", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "teez", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "teezak", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "zeby", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "zebb", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.HIGH, "stem": False},

    # Profanity & Insults
    {"term": "a5yat", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "akhyat", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "7ayawan", "cat": ViolationCategory.BULLYING, "sev": SeverityLevel.MEDIUM, "stem": True},
    {"term": "5awal", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "khawal", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "3ars", "cat": ViolationCategory.SEXUAL, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "3aars", "cat": ViolationCategory.SEXUAL, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "3rs", "cat": ViolationCategory.SEXUAL, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "m3aras", "cat": ViolationCategory.SEXUAL, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "ya3rs", "cat": ViolationCategory.SEXUAL, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "a7a", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "7a2eer", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.MEDIUM, "stem": True},
    {"term": "safel", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.MEDIUM, "stem": True},
    {"term": "wese5", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.MEDIUM, "stem": True},
    {"term": "wesekh", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.MEDIUM, "stem": True},
    {"term": "ahbal", "cat": ViolationCategory.BULLYING, "sev": SeverityLevel.LOW, "stem": True},
    {"term": "3abeet", "cat": ViolationCategory.BULLYING, "sev": SeverityLevel.LOW, "stem": True},
    {"term": "motakhalef", "cat": ViolationCategory.BULLYING, "sev": SeverityLevel.LOW, "stem": True},
]
