#!/usr/bin/env python3
"""
أداة لتوليد هاش آمن لكلمة مرور المشرف (scrypt) لاستخدامه في ملف .env
"""
import sys
import getpass
from security.auth import hash_admin_password


def main():
    print("=" * 60)
    print("🔐 أداة توليد تجزئة كلمة المرور الآمنة (Scrypt Password Hasher)")
    print("=" * 60)

    if len(sys.argv) > 1:
        raw_password = sys.argv[1]
    else:
        raw_password = getpass.getpass("أدخل كلمة المرور المراد تشفيرها: ")

    if not raw_password or not raw_password.strip():
        print("❌ خطأ: كلمة المرور لا يمكن أن تكون فارغة.")
        sys.exit(1)

    hashed = hash_admin_password(raw_password.strip())
    print("\n✅ تم توليد التجزئة الآمنة بنجاح:")
    print("-" * 60)
    print(hashed)
    print("-" * 60)
    print("\nقم بنسخ هذا السطر وضعه داخل ملف .env:")
    print(f"ADMIN_PASSWORD_HASH={hashed}\n")


if __name__ == "__main__":
    main()
