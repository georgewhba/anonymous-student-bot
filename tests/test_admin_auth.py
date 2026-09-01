import pytest
from config import Settings
from security.auth import (
    is_admin_session_valid,
    authenticate_admin_session,
    terminate_admin_session,
    hash_admin_password
)
from utils.key_generator import generate_encryption_key


def test_admin_auth_workflow():
    hashed_pass = hash_admin_password("MySecretPassword123")
    settings = Settings(
        bot_token="123456:test",
        channel_id=-100123,
        primary_admin_id=1420720902,
        moderator_ids=[987654321],
        admin_password_hash=hashed_pass,
        admin_session_expiry_minutes=60,
        encryption_key=generate_encryption_key()
    )

    admin_id = 1420720902
    non_admin_id = 999999999

    # 1. مستخدم غير مسجل كمشرف يفشل حتى مع الباسورد
    assert authenticate_admin_session(non_admin_id, "MySecretPassword123", settings) is False
    assert is_admin_session_valid(non_admin_id, settings) is False

    # 2. المشرف قبل إدخال الباسورد جلسته غير صالحة
    assert is_admin_session_valid(admin_id, settings) is False

    # 3. إدخال باسورد خاطئ يفشل
    assert authenticate_admin_session(admin_id, "WrongPassword", settings) is False
    assert is_admin_session_valid(admin_id, settings) is False

    # 4. إدخال الباسورد الصحيح ينجح ويوثق الجلسة
    assert authenticate_admin_session(admin_id, "MySecretPassword123", settings) is True
    assert is_admin_session_valid(admin_id, settings) is True

    # 5. تسجيل الخروج يقفل الجلسة
    terminate_admin_session(admin_id)
    assert is_admin_session_valid(admin_id, settings) is False
