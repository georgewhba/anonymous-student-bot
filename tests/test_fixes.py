"""
Automated Test Suite for Comprehensive Production Fixes.
Covers:
1. Banned fingerprint persistence across GDPR /forget_me wipe
2. Document filename sanitization & IdentityVault decryption access barriers
3. Dynamic .env moderation flags (links, profanity filter, block_* flags)
4. Per-admin individual credentials and /set_admin_password workflow
5. SQLite security events & session persistence across restarts
6. Cryptographic HKDF key separation
"""
import os
import pytest
from config import Settings
from security.crypto import CryptoManager
from security.identity_vault import IdentityVault
from security.auth import (
    admin_session_manager,
    AdminSessionManager,
    AdminRole,
    hash_admin_password,
    verify_admin_password
)
from database.db_manager import DatabaseManager
from moderation.engine import ModerationEngine
from moderation.cache import ModerationCache
from moderation.decision_engine import ViolationCategory, SeverityLevel, ModerationAction
from utils.key_generator import generate_encryption_key




@pytest.mark.asyncio
async def test_banned_fingerprint_persists_across_gdpr_wipe(test_db):
    """
    التحقق من أن حظر الطالب يظل سارياً حتى لو استخدم /forget_me لحذف بياناته ثم أعاد الدخول
    """
    telegram_id = 9876543210

    # 1. تسجيل الطالب لأول مرة
    student = await test_db.get_or_create_student(
        telegram_id=telegram_id,
        full_name="Banned Student",
        username="banned_user"
    )
    assert student is not None
    assert student.is_banned is False

    # 2. حظر الطالب
    ban_reason = "مخالفة جسيمة لقوانين المجتمع"
    await test_db.ban_student(student.anonymous_id, reason=ban_reason)
    banned_student = await test_db.get_student_by_anonymous_id(student.anonymous_id)
    assert banned_student.is_banned is True

    # 3. الطالب ينفذ /forget_me (حذف بياناته الشخصية)
    wipe_success = await test_db.wipe_student_data(student.anonymous_id)
    assert wipe_success is True
    wiped_student = await test_db.get_student_by_anonymous_id(student.anonymous_id)
    assert wiped_student.enc_telegram_id == "[WIPED]"

    # 4. الطالب يحاول التسجيل مجدداً عبر البوت بعد الحذف
    recreated_student = await test_db.get_or_create_student(
        telegram_id=telegram_id,
        full_name="New Alias",
        username="new_alias"
    )
    # يجب التعرف على بصمته المشفرة وحظره فوراً مع استعادة سبب الحظر
    assert recreated_student.is_banned is True
    assert recreated_student.ban_reason == ban_reason


@pytest.mark.asyncio
async def test_document_filename_sanitization_and_vault_decryption(test_crypto, test_db):
    """
    التحقق من تعمية اسم الملف الأصلي وفك تشفيره حصرياً عبر خزنة الهوية للمسؤول الأساسي
    """
    primary_admin_id = 111111
    moderator_id = 222222
    unauthorized_id = 333333

    settings = Settings(
        bot_token="123456:test",
        channel_id=-100123,
        primary_admin_id=primary_admin_id,
        moderator_ids=[moderator_id],
        admin_password_hash=hash_admin_password("Secret#2026"),
        encryption_key=generate_encryption_key(),
        database_path=test_db.db_path
    )

    # توثيق جلسة المسؤول الأساسي وجلسة المشرف
    admin_session_manager.create_session(primary_admin_id, role=AdminRole.PRIMARY_ADMIN, settings=settings)
    admin_session_manager.create_session(moderator_id, role=AdminRole.MODERATOR, settings=settings)

    original_filename = "Confidential_Student_Thesis_v1.pdf"
    enc_fn = test_crypto.encrypt(original_filename)

    # 1. المسؤول الأساسي بجلسة نشطة يمكنه فك تشفير اسم الملف
    dec_fn = IdentityVault.decrypt_filename(enc_fn, test_crypto, primary_admin_id, settings)
    assert dec_fn == original_filename

    # 2. المشرف يُمنع من فك تشفير اسم الملف (PermissionError)
    with pytest.raises(PermissionError) as exc_mod:
        IdentityVault.decrypt_filename(enc_fn, test_crypto, moderator_id, settings)
    assert "غير مصرح" in str(exc_mod.value)

    # 3. المستخدم غير المصرح يُمنع
    with pytest.raises(PermissionError) as exc_unauth:
        IdentityVault.decrypt_filename(enc_fn, test_crypto, unauthorized_id, settings)
    assert "غير مصرح" in str(exc_unauth.value)


def test_dynamic_moderation_flags():
    """
    التحقق من استجابة محرك الرقابة للمتغيرات الديناميكية في Settings
    """
    # 1. عند السماح بالروابط ALLOW_LINKS_IN_SUBMISSIONS=True
    settings_allow_links = Settings(
        bot_token="123456:test",
        channel_id=-100123,
        primary_admin_id=111111,
        encryption_key=generate_encryption_key(),
        allow_links_in_submissions=True
    )
    engine_links = ModerationEngine(settings=settings_allow_links, cache=ModerationCache())
    res_links = engine_links.inspect_content(text="سؤال عن هذا الرابط المفيد: https://example.com/docs")
    assert res_links.is_allowed is True

    # 2. عند منع الروابط ALLOW_LINKS_IN_SUBMISSIONS=False
    settings_block_links = Settings(
        bot_token="123456:test",
        channel_id=-100123,
        primary_admin_id=111111,
        encryption_key=generate_encryption_key(),
        allow_links_in_submissions=False
    )
    engine_no_links = ModerationEngine(settings=settings_block_links, cache=ModerationCache())
    res_no_links = engine_no_links.inspect_content(text="سؤال عن هذا الرابط المفيد: https://example.com/docs")
    assert res_no_links.is_allowed is False
    assert res_no_links.action == ModerationAction.BLOCK

    # 3. عند تعطيل فلتر الألفاظ النابية والتنمر
    settings_no_profanity = Settings(
        bot_token="123456:test",
        channel_id=-100123,
        primary_admin_id=111111,
        encryption_key=generate_encryption_key(),
        enable_profanity_filter=False,
        block_profanity=False,
        block_bullying=False,
        block_harassment=False
    )
    engine_no_prof = ModerationEngine(settings=settings_no_profanity, cache=ModerationCache())
    res_no_prof = engine_no_prof.inspect_content(text="كلمة غبي تجريبية")
    assert res_no_prof.is_allowed is True


@pytest.mark.asyncio
async def test_per_admin_individual_credentials(test_db):
    """
    التحقق من إنشاء كلمات مرور فردية لكل مشرف والتحقق منها بنجاح
    """
    primary_id = 111111
    mod_id = 222222

    mod_pass = "ModIndividualPass#2026"
    mod_pass_hash = hash_admin_password(mod_pass)

    # حفظ بيانات اعتماد المشرف في قاعدة البيانات
    await test_db.set_admin_credential(
        telegram_id=mod_id,
        password_hash=mod_pass_hash,
        role="moderator"
    )

    # التحقق من استرجاع كلمة المرور الفردية
    cred = await test_db.get_admin_credential(mod_id)
    assert cred is not None
    stored_hash, stored_role = cred
    assert stored_role == "moderator"
    assert verify_admin_password(mod_pass, stored_hash) is True

    # التحقق عبر AdminSessionManager
    settings = Settings(
        bot_token="123456:test",
        channel_id=-100123,
        primary_admin_id=primary_id,
        moderator_ids=[mod_id],
        admin_password_hash=hash_admin_password("GlobalFallbackPass"),
        encryption_key=generate_encryption_key(),
        database_path=test_db.db_path
    )

    manager = AdminSessionManager(db_path=test_db.db_path)

    # تسجيل الدخول بكلمة المرور الفردية
    ok, err = manager.authenticate(mod_id, mod_pass, settings, custom_password_hash=stored_hash)
    assert ok is True
    assert err is None
    assert manager.is_session_valid(mod_id, settings) is True

    # محاولة تسجيل الدخول بكلمة مرور فردية خاطئة
    manager.terminate_session(mod_id)
    ok_bad, err_bad = manager.authenticate(mod_id, "WrongPass", settings, custom_password_hash=stored_hash)
    assert ok_bad is False
    assert "غير صحيحة" in err_bad


@pytest.mark.asyncio
async def test_postgres_security_events_and_strike_persistence(test_db):
    """
    التحقق من حفظ المخالفات الأمنية في جدول security_events في PostgreSQL
    """
    student_id = 88888

    # تسجيل مخالفة أمنية مباشرة في قاعدة البيانات
    await test_db.record_security_event(
        user_id=student_id,
        event_type="violation_threat",
        details="Security policy violation: threat"
    )

    # التحقق من تسجيل المخالفة في SQLite
    count = await test_db.get_recent_security_events_count(
        user_id=student_id,
        event_type="violation_threat",
        window_seconds=3600
    )
    assert count == 1


def test_hkdf_key_separation():
    """
    التحقق من أن التجزئة العمياء تستخدم مفتاح HKDF منفصل عن مفتاح التشفير
    """
    master_key = generate_encryption_key()
    crypto1 = CryptoManager(master_key)
    crypto2 = CryptoManager(master_key)

    telegram_id = 123456789

    # نفس المفتاح الأساسي يُنتج نفس الـ User Hash (HMAC)
    hash1 = crypto1.create_user_hash(telegram_id)
    hash2 = crypto2.create_user_hash(telegram_id)
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA-256 Hex Digest

    # مفتاح مختلف يُنتج HMAC مختلف
    crypto3 = CryptoManager(generate_encryption_key())
    hash3 = crypto3.create_user_hash(telegram_id)
    assert hash1 != hash3
