"""
Role-Based Access Control and Authentication Tests.
Tests password hashing, lockout mechanisms, session lifecycles, and IdentityVault barriers.
"""
import pytest
from config import Settings
from security.auth import (
    hash_admin_password,
    verify_admin_password,
    AdminSessionManager,
    AdminRole
)
from security.identity_vault import IdentityVault, DecryptedIdentity
from security.crypto import CryptoManager
from database.models import StudentModel
from utils.key_generator import generate_encryption_key


def test_password_hashing_and_verification():
    raw_pass = "Super#Secret$Password2026"
    hashed = hash_admin_password(raw_pass)

    assert hashed.startswith("scrypt$")
    assert verify_admin_password(raw_pass, hashed) is True
    assert verify_admin_password("WrongPassword123", hashed) is False
    assert verify_admin_password("", hashed) is False


def test_admin_session_manager_and_rbac():
    raw_pass = "MySecretAdminPass"
    hashed = hash_admin_password(raw_pass)

    settings = Settings(
        bot_token="123456:test",
        channel_id=-100123,
        primary_admin_id=11111,
        moderator_ids=[22222, 33333],
        admin_password_hash=hashed,
        admin_session_expiry_minutes=60,
        encryption_key=generate_encryption_key()
    )

    manager = AdminSessionManager()
    primary_id = 11111
    mod_id = 22222
    stranger_id = 99999

    # 1. مستخدم غريب لا يمكنه تسجيل الدخول حتى لو خمن كلمة المرور
    ok, err = manager.authenticate(stranger_id, raw_pass, settings)
    assert ok is False
    assert "غير مصرح" in err

    # 2. المشرف والمسؤول قبل إدخال كلمة المرور لا يملكان جلسة سارية
    assert manager.is_session_valid(primary_id, settings) is False
    assert manager.is_session_valid(mod_id, settings) is False

    # 3. إدخال كلمة مرور خاطئة يفشل
    ok, err = manager.authenticate(primary_id, "WrongPass", settings)
    assert ok is False
    assert "غير صحيحة" in err

    # 4. تسجيل الدخول بكلمة المرور الصحيحة
    ok, _ = manager.authenticate(primary_id, raw_pass, settings)
    assert ok is True
    assert manager.is_session_valid(primary_id, settings) is True
    assert manager.is_primary_admin(primary_id, settings) is True
    assert manager.get_role_for_user(primary_id, settings) == AdminRole.PRIMARY_ADMIN

    # 5. توثيق جلسة المشرف
    ok, _ = manager.authenticate(mod_id, raw_pass, settings)
    assert ok is True
    assert manager.is_session_valid(mod_id, settings) is True
    assert manager.is_primary_admin(mod_id, settings) is False
    assert manager.is_moderator_or_higher(mod_id, settings) is True

    # 6. إنهاء الجلسة (Logout)
    manager.terminate_session(primary_id)
    assert manager.is_session_valid(primary_id, settings) is False


def test_brute_force_lockout():
    manager = AdminSessionManager()
    settings = Settings(
        bot_token="123456:test",
        channel_id=-100123,
        primary_admin_id=11111,
        admin_password_hash=hash_admin_password("CorrectPass"),
        encryption_key=generate_encryption_key()
    )
    user_id = 11111

    # محاولات فاشلة حتى الإقفال
    for i in range(5):
        ok, _ = manager.authenticate(user_id, "BadPass", settings)
        assert ok is False

    # المحاولة السادسة حتى مع كلمة المرور الصحيحة تُقفل بالحظر المؤقت
    ok, err = manager.authenticate(user_id, "CorrectPass", settings)
    assert ok is False
    assert "مقفل مؤقتاً" in err
    assert manager.get_lockout_remaining_seconds(user_id) > 0


def test_identity_vault_access_barrier():
    key = generate_encryption_key()
    crypto = CryptoManager(key)
    settings = Settings(
        bot_token="123456:test",
        channel_id=-100123,
        primary_admin_id=1001,
        moderator_ids=[2002],
        admin_password_hash=hash_admin_password("Secret123"),
        encryption_key=key
    )

    # إنشاء سجل طالب مشفر
    student = StudentModel(
        id=1,
        anonymous_id=105,
        user_hash=crypto.create_user_hash(555666777),
        enc_telegram_id=crypto.encrypt(555666777),
        enc_full_name=crypto.encrypt("خالد عبد الله"),
        enc_username=crypto.encrypt("khaled_a")
    )

    manager = AdminSessionManager()
    # 1. المسؤول الأساسي يوثق جلسته
    manager.authenticate(1001, "Secret123", settings)

    # يمكن للمسؤول الأساسي كشف الهوية
    from security.auth import admin_session_manager
    admin_session_manager.authenticate(1001, "Secret123", settings)

    identity: DecryptedIdentity = IdentityVault.resolve_student_identity(
        student=student,
        crypto=crypto,
        requesting_user_id=1001,
        settings=settings
    )
    assert identity.anonymous_id == 105
    assert identity.telegram_id == 555666777
    assert identity.full_name == "خالد عبد الله"
    assert identity.username == "khaled_a"

    # 2. المشرف حتى مع جلسة موثقة يُمنع تماماً من كشف الهوية (PermissionError)
    admin_session_manager.authenticate(2002, "Secret123", settings)
    with pytest.raises(PermissionError):
        IdentityVault.resolve_student_identity(
            student=student,
            crypto=crypto,
            requesting_user_id=2002,
            settings=settings
        )

    # 3. مستخدم غريب يُمنع
    with pytest.raises(PermissionError):
        IdentityVault.resolve_student_identity(
            student=student,
            crypto=crypto,
            requesting_user_id=9999,
            settings=settings
        )
