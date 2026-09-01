"""
English Categorized Vocabulary Dictionary.
Covers Explicit, Sexual, Profanity, Insults, Harassment, Bullying, Threats, Hate Speech, and Self-Harm.
"""
from typing import List, Dict, Any
from moderation.models import ViolationCategory, SeverityLevel

ENGLISH_TERMS: List[Dict[str, Any]] = [
    # =========================================================================
    # 1. EXPLICIT & SEXUAL CONTENT
    # =========================================================================
    {"term": "porn", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "porno", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "pornography", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "sex", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.HIGH, "stem": False},
    {"term": "sexy", "cat": ViolationCategory.SEXUAL, "sev": SeverityLevel.MEDIUM, "stem": True},
    {"term": "pussy", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "dick", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "cock", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": False},
    {"term": "boob", "cat": ViolationCategory.SEXUAL, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "boobs", "cat": ViolationCategory.SEXUAL, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "nude", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "nudes", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "naked", "cat": ViolationCategory.SEXUAL, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "blowjob", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "cum", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": False},
    {"term": "slut", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "whore", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "dildo", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "hentai", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "orgasm", "cat": ViolationCategory.SEXUAL, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "milf", "cat": ViolationCategory.SEXUAL, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "xxx", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.CRITICAL, "stem": False},

    # =========================================================================
    # 2. PROFANITY, INSULTS & BULLYING
    # =========================================================================
    {"term": "fuck", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "fucking", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "fucker", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "motherfucker", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "bitch", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "bitches", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "shit", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "bastard", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "cunt", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "asshole", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "ass", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": False},
    {"term": "dumbass", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.MEDIUM, "stem": True},
    {"term": "retard", "cat": ViolationCategory.SLUR, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "idiot", "cat": ViolationCategory.BULLYING, "sev": SeverityLevel.LOW, "stem": True},
    {"term": "stupid", "cat": ViolationCategory.BULLYING, "sev": SeverityLevel.LOW, "stem": True},
    {"term": "moron", "cat": ViolationCategory.BULLYING, "sev": SeverityLevel.LOW, "stem": True},
    {"term": "stfu", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": False},
    {"term": "gtfo", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": False},
    {"term": "wtf", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.MEDIUM, "stem": False},
    {"term": "fk", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": False},
    {"term": "fuk", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": False},
    {"term": "fck", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": False},
    {"term": "fc", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": False},
    {"term": "btch", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": False},
    {"term": "bch", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": False},
    {"term": "dck", "cat": ViolationCategory.EXPLICIT, "sev": SeverityLevel.HIGH, "stem": False},
    {"term": "sh1t", "cat": ViolationCategory.PROFANITY, "sev": SeverityLevel.HIGH, "stem": False},

    # =========================================================================
    # 3. THREATS, VIOLENCE & SELF-HARM
    # =========================================================================
    {"term": "kill you", "cat": ViolationCategory.THREAT, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "murder", "cat": ViolationCategory.VIOLENCE, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "suicide", "cat": ViolationCategory.SELF_HARM, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "kill myself", "cat": ViolationCategory.SELF_HARM, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "cut myself", "cat": ViolationCategory.SELF_HARM, "sev": SeverityLevel.CRITICAL, "stem": True},

    {"term": "kys", "cat": ViolationCategory.SELF_HARM, "sev": SeverityLevel.CRITICAL, "stem": False},
    {"term": "loser", "cat": ViolationCategory.INSULT, "sev": SeverityLevel.MEDIUM, "stem": True},
    {"term": "scum", "cat": ViolationCategory.HATE, "sev": SeverityLevel.HIGH, "stem": True},
    {"term": "subhuman", "cat": ViolationCategory.HATE, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "kill all", "cat": ViolationCategory.THREAT, "sev": SeverityLevel.CRITICAL, "stem": True},

    # =========================================================================
    # 4. HATE SPEECH & SLURS
    # =========================================================================
    {"term": "nigger", "cat": ViolationCategory.HATE, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "nigga", "cat": ViolationCategory.HATE, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "faggot", "cat": ViolationCategory.HATE, "sev": SeverityLevel.CRITICAL, "stem": True},
    {"term": "kike", "cat": ViolationCategory.HATE, "sev": SeverityLevel.CRITICAL, "stem": True},
]
