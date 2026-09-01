#!/usr/bin/env python3
"""
أداة لتوليد مفتاح تشفير Fernet آمن (32-byte urlsafe base64) للاستخدام في ملف .env
"""
from cryptography.fernet import Fernet


def generate_encryption_key() -> str:
    """توليد مفتاح Fernet آمن"""
    return Fernet.generate_key().decode("utf-8")


if __name__ == "__main__":
    key = generate_encryption_key()
    print("=" * 60)
    print("🔑 تم توليد مفتاح التشفير الآمن بنجاح (Fernet Key):")
    print(key)
    print("=" * 60)
    print("قم بنسخ هذا المفتاح وضعه في ملف .env كالتالي:")
    print(f"ENCRYPTION_KEY={key}")
    print("=" * 60)
