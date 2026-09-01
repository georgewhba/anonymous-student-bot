import pytest
from database.crypto import CryptoManager
from utils.key_generator import generate_encryption_key


def test_crypto_encryption_and_decryption():
    key = generate_encryption_key()
    crypto = CryptoManager(key)

    original_text = "أحمد علي محمود"
    encrypted = crypto.encrypt(original_text)
    assert encrypted is not None
    assert encrypted != original_text

    decrypted = crypto.decrypt(encrypted)
    assert decrypted == original_text


def test_crypto_integer_handling():
    key = generate_encryption_key()
    crypto = CryptoManager(key)

    original_id = 9876543210
    encrypted = crypto.encrypt(original_id)
    assert encrypted is not None

    decrypted_int = crypto.decrypt_int(encrypted)
    assert decrypted_int == original_id


def test_crypto_deterministic_hash():
    key = generate_encryption_key()
    crypto = CryptoManager(key)

    user_id = 123456789
    hash1 = crypto.create_user_hash(user_id)
    hash2 = crypto.create_user_hash(user_id)

    assert hash1 == hash2
    assert len(hash1) == 64  # SHA256 hex string


def test_crypto_invalid_key_or_corrupted_data():
    key1 = generate_encryption_key()
    key2 = generate_encryption_key()

    crypto1 = CryptoManager(key1)
    crypto2 = CryptoManager(key2)

    enc = crypto1.encrypt("بيانات سرية")
    # محاولة فك التشفير بمفتاح مختلف
    dec = crypto2.decrypt(enc)
    assert "خطأ" in dec or dec is None
