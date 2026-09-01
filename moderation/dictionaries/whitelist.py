"""
Academic Whitelist and Contextual False-Positive Guards.
Contains legitimate academic, technical, and linguistic words that could otherwise trigger naive substring filters.
"""
from typing import Set

ACADEMIC_WHITELIST_TOKENS: Set[str] = {
    # Arabic legitimate words containing sub-tokens
    "اكبر", "أكبر", "كبر", "تكبير",
    "تقويم", "التقويم", "قوم",
    "كتاب", "الكتاب", "كتيب", "مكتبة", "مكتبه",
    "عكس", "معكوس", "انعكاس",
    "مسالة", "مسألة", "اسئلة", "أسئلة", "سؤال",
    "كسر", "انكسار", "الانكسار", "تكسير", "التكسير", "كسور", "الكسور", "انكسارات",
    "كسل", "الكسل", "كسلان", "الكسلان",
    "كسب", "الكسب", "اكتساب", "الاكتساب", "مكسب", "المكسب", "مكاسب",
    "شروط", "الشروط", "شرط", "الشرط", "مشروط", "اشتراط",
    "زبده", "زبدة", "الزبدة", "زبرجد", "الزبرجد",
    "سفينة", "سفينه",
    "تفسير", "فسر",
    "مناقشة", "مناقشه",
    "كلمة", "كلمه", "كلام", "الكلام", "الكلمة", "الكلمه", "كلمات", "الكلمات",
    "لغة", "لغه", "اللغة", "اللغه", "معنى", "المعنى", "طريقة", "طريقه", "استخدام",

    # English legitimate words containing sub-tokens
    "assess", "assessment", "assessing", "assessor",
    "class", "classes", "classical", "classic", "classroom",
    "pass", "passage", "passing", "passive", "passport", "password",
    "compass", "compassion",
    "grass", "glass", "brass", "mass", "massive", "bass",
    "asset", "assets",
    "assist", "assistant", "assistance",
    "assume", "assumption",
    "association", "associate", "associates",
    "discuss", "discussion", "discussing",
    "cassette", "embassy", "harass",
    "document", "documentation",
    "analysis", "analytic",
    "cockpit", "cocktail",
    "scunthorpe",
}
