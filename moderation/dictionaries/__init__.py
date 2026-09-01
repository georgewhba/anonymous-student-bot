"""
Moderation Dictionaries Package Exports.
"""
from moderation.dictionaries.arabic import ARABIC_TERMS
from moderation.dictionaries.english import ENGLISH_TERMS
from moderation.dictionaries.arabizi import ARABIZI_TERMS
from moderation.dictionaries.phrases import ABUSIVE_PHRASES
from moderation.dictionaries.whitelist import ACADEMIC_WHITELIST_TOKENS

# Aliases for compatibility
ARABIC_DICTIONARY = ARABIC_TERMS
ENGLISH_DICTIONARY = ENGLISH_TERMS
ARABIZI_DICTIONARY = ARABIZI_TERMS

__all__ = [
    "ARABIC_TERMS",
    "ENGLISH_TERMS",
    "ARABIZI_TERMS",
    "ABUSIVE_PHRASES",
    "ACADEMIC_WHITELIST_TOKENS",
    "ARABIC_DICTIONARY",
    "ENGLISH_DICTIONARY",
    "ARABIZI_DICTIONARY",
]
