"""
Adversarial Corpus Automated Test Runner.
Loads corpus JSON files from tests/moderation/corpus/ and executes strict acceptance assertions.
"""
import os
import json
import pytest
from moderation.engine import moderation_engine


CORPUS_DIR = os.path.join(os.path.dirname(__file__), "corpus")


def load_corpus(filename: str):
    path = os.path.join(CORPUS_DIR, filename)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize("item", load_corpus("adversarial_arabic.json"))
def test_corpus_adversarial_arabic(item):
    text = item["text"]
    result = moderation_engine.inspect_content(text)
    assert result.is_allowed == item["expected_allowed"], f"Failed on Arabic corpus: '{text}' (Reasons: {result.reasons})"


@pytest.mark.parametrize("item", load_corpus("adversarial_english.json"))
def test_corpus_adversarial_english(item):
    text = item["text"]
    result = moderation_engine.inspect_content(text)
    assert result.is_allowed == item["expected_allowed"], f"Failed on English corpus: '{text}' (Reasons: {result.reasons})"


@pytest.mark.parametrize("item", load_corpus("adversarial_arabizi.json"))
def test_corpus_adversarial_arabizi(item):
    text = item["text"]
    result = moderation_engine.inspect_content(text)
    assert result.is_allowed == item["expected_allowed"], f"Failed on Arabizi corpus: '{text}' (Reasons: {result.reasons})"


@pytest.mark.parametrize("item", load_corpus("adversarial_obfuscation.json"))
def test_corpus_adversarial_obfuscation(item):
    text = item["text"]
    result = moderation_engine.inspect_content(text)
    assert result.is_allowed == item["expected_allowed"], f"Failed on Obfuscation corpus: '{text}' (Reasons: {result.reasons})"


@pytest.mark.parametrize("item", load_corpus("academic_clean_corpus.json"))
def test_corpus_academic_clean_immunity(item):
    text = item["text"]
    result = moderation_engine.inspect_content(text)
    assert result.is_allowed == item["expected_allowed"], f"False positive on Clean Academic corpus: '{text}' (Reasons: {result.reasons})"
