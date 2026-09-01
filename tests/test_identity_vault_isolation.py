"""
Identity Vault Isolation Test Suite.
Verifies that database repositories strictly return isolated records without decrypted PII,
and only IdentityVault.resolve_student_identity() decrypts PII for authenticated Primary Admin.
"""
import pytest
from database.db_manager import DatabaseManager
from security.crypto import CryptoManager
from security.identity_vault import IdentityVault, DecryptedIdentity
from security.auth import admin_session_manager
from utils.key_generator import generate_encryption_key
from config import Settings




@pytest.fixture
def mock_settings():
    return Settings(
        bot_token="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        channel_id=-1001987654321,
        encryption_key=generate_encryption_key(),
        primary_admin_id=999999,
        moderator_ids=[888888],
        admin_password="PrimaryAdminSecret2026!"
    )


@pytest.mark.asyncio
async def test_repository_methods_return_zero_pii(vault_db):
    """التحقق من أن استعلامات قاعدة البيانات العامة لا تفك تشفير بيانات PII أبداً"""
    db = vault_db
    created = await db.get_or_create_student(
        telegram_id=777111222,
        full_name="طالب مجهول الهوية",
        username="vault_student"
    )

    assert created.anonymous_id == 101
    assert created.dec_telegram_id is None
    assert created.dec_full_name is None
    assert created.dec_username is None

    # استرجاع عبر الرقم المجهول
    by_anon = await db.get_student_by_anonymous_id(101)
    assert by_anon is not None
    assert by_anon.dec_telegram_id is None
    assert by_anon.dec_full_name is None
    assert by_anon.dec_username is None

    # استرجاع عبر معرف تيليجرام
    by_tid = await db.get_student_by_telegram_id(777111222)
    assert by_tid is not None
    assert by_tid.dec_telegram_id is None

    # استرجاع عبر الدالة العامة الصريحة
    public_s = await db.get_public_student_by_anonymous_id(101)
    assert public_s is not None
    assert public_s.dec_telegram_id is None


@pytest.mark.asyncio
async def test_identity_vault_resolution_primary_admin(vault_db, test_crypto, mock_settings):
    """التحقق من نجاح كشف الهوية المشفرة للمسؤول الأساسي بجلسة صالحة"""
    db = vault_db
    student = await db.get_or_create_student(
        telegram_id=777111222,
        full_name="علي حسن",
        username="ali_hassan"
    )

    # توثيق جلسة المسؤول الأساسي
    auth_ok, _ = admin_session_manager.authenticate(mock_settings.primary_admin_id, "PrimaryAdminSecret2026!", mock_settings)
    assert auth_ok is True

    identity: DecryptedIdentity = IdentityVault.resolve_student_identity(
        student=student,
        crypto=test_crypto,
        requesting_user_id=mock_settings.primary_admin_id,
        settings=mock_settings
    )

    assert identity.anonymous_id == 101
    assert identity.telegram_id == 777111222
    assert identity.full_name == "علي حسن"
    assert identity.username == "ali_hassan"
    assert identity.is_banned is False


@pytest.mark.asyncio
async def test_identity_vault_blocks_moderators_and_unauthorized_users(vault_db, test_crypto, mock_settings):
    """التحقق من حظر المشرفين والطلاب من كشف الهوية المشفرة ومنع تسريب البيانات"""
    db = vault_db
    student = await db.get_or_create_student(
        telegram_id=777111222,
        full_name="علي حسن",
        username="ali_hassan"
    )

    # 1. محاولة المشرف (Moderator)
    auth_mod_ok, _ = admin_session_manager.authenticate(888888, "PrimaryAdminSecret2026!", mock_settings)
    assert auth_mod_ok is True
    with pytest.raises(PermissionError) as exc_mod:
        IdentityVault.resolve_student_identity(
            student=student,
            crypto=test_crypto,
            requesting_user_id=888888,
            settings=mock_settings
        )
    assert "غير مصرح" in str(exc_mod.value)

    # 2. محاولة مستخدم عادي / طالب
    with pytest.raises(PermissionError) as exc_user:
        IdentityVault.resolve(
            student=student,
            crypto=test_crypto,
            requesting_user_id=123456789,
            settings=mock_settings
        )
    assert "غير مصرح" in str(exc_user.value)


@pytest.mark.asyncio
async def test_identity_vault_system_notification_and_dm(vault_db, test_crypto, mock_settings):
    """التحقق من عمل إشعارات النظام والمراسلة المباشرة المقيدة"""
    from unittest.mock import AsyncMock

    db = vault_db
    student = await db.get_or_create_student(
        telegram_id=777111222,
        full_name="علي حسن",
        username="ali_hassan"
    )

    mock_bot = AsyncMock()
    mock_bot.send_message.return_value = AsyncMock()

    # 1. إشعار نظام
    sent_sys = await IdentityVault.send_system_notification(
        bot=mock_bot,
        student=student,
        crypto=test_crypto,
        text="تنبيه نظام"
    )
    assert sent_sys is True
    mock_bot.send_message.assert_called_with(chat_id=777111222, text="تنبيه نظام", parse_mode="HTML")

    # 2. رسالة خاصة من Primary Admin
    admin_session_manager.create_session(mock_settings.primary_admin_id)
    sent_dm = await IdentityVault.send_direct_message(
        bot=mock_bot,
        student=student,
        crypto=test_crypto,
        requesting_user_id=mock_settings.primary_admin_id,
        settings=mock_settings,
        text="رسالة خاصة"
    )
    assert sent_dm is True

    # 3. رسالة خاصة من Moderator (يجب أن تفشل بترخيص)
    admin_session_manager.create_session(888888)
    with pytest.raises(PermissionError):
        await IdentityVault.send_direct_message(
            bot=mock_bot,
            student=student,
            crypto=test_crypto,
            requesting_user_id=888888,
            settings=mock_settings,
            text="رسالة خاصة غير مصرحة"
        )

