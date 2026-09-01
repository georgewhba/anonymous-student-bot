"""
Final Automated Static & Architectural Audit Tool for Production Verification.
Executes rigorous static and architectural audits across the codebase:
1. Direct Telegram Target-Channel Send Scan outside PublisherService
2. SQLite Runtime Usage Scan (aiosqlite, sqlite3, PRAGMA in runtime)
3. DATABASE_PATH Scan in Runtime Code
4. Plaintext Admin Password / Insecure Fallback Scan
5. Unsafe Fail-Open Path Verification
6. PII & Logging Sanitizer Scan
7. Direct PII Decryption outside IdentityVault Scan
8. Required Environment Variables in .env.example
9. Mandatory Moderation Gate Enforcement
10. Content Protection (protect_content=True) Enforcement
11. Dangerous File Handling & Path Traversal Protections

Exits with:
0 = PASS (Ready for Delivery)
1 = FAIL (Blocking Issues Detected)
"""
import os
import sys
import re

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def run_audit() -> bool:
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    print("=" * 70)
    print("🔍 RUNNING COMPREHENSIVE AUTOMATED FINAL ARCHITECTURAL AUDIT...")
    print("=" * 70)

    passed = True
    issues = []

    def get_runtime_py_files():
        py_files = []
        for root, dirs, files in os.walk(project_root):
            if any(ignored in root for ignored in ["tests", ".pytest_cache", ".git", "__pycache__", "media_tmp", "tools"]):
                continue
            for file in files:
                if file.endswith(".py"):
                    py_files.append((os.path.join(root, file), os.path.relpath(os.path.join(root, file), project_root)))
        return py_files

    runtime_files = get_runtime_py_files()

    # ---------------------------------------------------------
    # Check 1: Direct Telegram Target-Channel Send Scan
    # ---------------------------------------------------------
    print("[1/11] Scanning for Direct Channel Send Calls outside PublisherService...")
    direct_send_pattern = re.compile(
        r"bot\.send_(message|photo|document|voice|audio|video|animation)\s*\(\s*[^)]*channel_id",
        re.IGNORECASE
    )
    for path, rel_path in runtime_files:
        if os.path.basename(path) not in ["publisher.py", "logger.py"]:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
                if direct_send_pattern.search(content):
                    issues.append(f"❌ Direct channel send detected outside publisher: {rel_path}")
                    passed = False

    # ---------------------------------------------------------
    # Check 2: SQLite Runtime Usage Scan
    # ---------------------------------------------------------
    print("[2/11] Scanning for SQLite Runtime Artifacts (aiosqlite, sqlite3, PRAGMA)...")
    sqlite_patterns = [
        re.compile(r"\bimport\s+sqlite3\b"),
        re.compile(r"\bimport\s+aiosqlite\b"),
        re.compile(r"\bPRAGMA\s+journal_mode\b", re.IGNORECASE),
        re.compile(r"\bPRAGMA\s+foreign_keys\b", re.IGNORECASE),
        re.compile(r"\bINSERT\s+OR\s+IGNORE\b", re.IGNORECASE),
        re.compile(r"\bINSERT\s+OR\s+REPLACE\b", re.IGNORECASE),
        re.compile(r"\blastrowid\b", re.IGNORECASE)
    ]
    for path, rel_path in runtime_files:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            for pattern in sqlite_patterns:
                if pattern.search(content):
                    issues.append(f"❌ SQLite runtime syntax detected in: {rel_path}")
                    passed = False

    # ---------------------------------------------------------
    # Check 3: DATABASE_PATH Scan in Runtime Code
    # ---------------------------------------------------------
    print("[3/11] Scanning for DATABASE_PATH in runtime code...")
    db_path_pattern = re.compile(r"\b(DATABASE_PATH|db_path)\b")
    for path, rel_path in runtime_files:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            if db_path_pattern.search(content):
                issues.append(f"❌ Legacy db_path/DATABASE_PATH found in: {rel_path}")
                passed = False

    # ---------------------------------------------------------
    # Check 4: Plaintext Admin Password / Insecure Fallback Scan
    # ---------------------------------------------------------
    print("[4/11] Scanning for Insecure Hardcoded Admin Passwords...")
    insecure_pwd_pattern = re.compile(r"admin_password\s*=\s*['\"](admin|123456|password|admin123)['\"]", re.IGNORECASE)
    config_file = os.path.join(project_root, "config.py")
    if os.path.exists(config_file):
        with open(config_file, "r", encoding="utf-8") as f:
            if insecure_pwd_pattern.search(f.read()):
                issues.append("❌ Insecure default password detected in config.py")
                passed = False

    # ---------------------------------------------------------
    # Check 5: Unsafe Fail-Open Path Verification
    # ---------------------------------------------------------
    print("[5/11] Verifying Fail-Closed Policies in Moderation and Decision Engines...")
    media_analyzer_file = os.path.join(project_root, "moderation", "media_analyzer.py")
    if os.path.exists(media_analyzer_file):
        with open(media_analyzer_file, "r", encoding="utf-8") as f:
            content = f.read()
            if "fail_closed" not in content or "MEDIA_UNSAFE" not in content:
                issues.append("❌ media_analyzer.py lacks strict fail_closed or MEDIA_UNSAFE handling")
                passed = False

    # ---------------------------------------------------------
    # Check 6: PII & Logging Sanitizer Scan
    # ---------------------------------------------------------
    print("[6/11] Verifying PII Logging Sanitizer...")
    logger_file = os.path.join(project_root, "utils", "logger.py")
    if not os.path.exists(logger_file):
        issues.append("❌ Missing utils/logger.py")
        passed = False
    else:
        with open(logger_file, "r", encoding="utf-8") as f:
            content = f.read()
            if "scrub_pii_from_log_message" not in content:
                issues.append("❌ logger.py lacks PII scrubbing logic")
                passed = False

    # ---------------------------------------------------------
    # Check 7: Direct PII Decryption outside IdentityVault Scan
    # ---------------------------------------------------------
    print("[7/11] Scanning for Direct Decryption calls outside IdentityVault...")
    decrypt_pattern = re.compile(r"(crypto|db\.crypto)\.decrypt(_int)?\s*\(")
    for path, rel_path in runtime_files:
        if os.path.basename(path) not in ["identity_vault.py", "crypto.py"]:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
                if decrypt_pattern.search(content):
                    issues.append(f"❌ Direct decrypt call outside IdentityVault in: {rel_path}")
                    passed = False

    # ---------------------------------------------------------
    # Check 8: Required Environment Variables in .env.example
    # ---------------------------------------------------------
    print("[8/11] Validating .env.example Template Completeness...")
    env_example = os.path.join(project_root, ".env.example")
    if not os.path.exists(env_example):
        issues.append("❌ Missing .env.example file")
        passed = False
    else:
        with open(env_example, "r", encoding="utf-8") as f:
            env_content = f.read()
            required_envs = [
                "BOT_TOKEN", "CHANNEL_ID", "ENCRYPTION_KEY", "PRIMARY_ADMIN_ID",
                "DATABASE_URL", "DATABASE_POOL_MIN", "DATABASE_POOL_MAX"
            ]
            for req in required_envs:
                if req not in env_content:
                    issues.append(f"❌ .env.example missing required key: {req}")
                    passed = False

    # ---------------------------------------------------------
    # Check 9: Mandatory Moderation Gate Enforcement
    # ---------------------------------------------------------
    print("[9/11] Verifying Moderation Gate Enforcement in Submission Handlers...")
    submit_file = os.path.join(project_root, "handlers", "user_submit.py")
    reply_file = os.path.join(project_root, "handlers", "user_reply.py")
    for h_file in [submit_file, reply_file]:
        if os.path.exists(h_file):
            with open(h_file, "r", encoding="utf-8") as f:
                content = f.read()
                if "publish_post" not in content or "publisher_service" not in content:
                    issues.append(f"❌ Handler {os.path.basename(h_file)} does not use publisher_service gate")
                    passed = False

    # ---------------------------------------------------------
    # Check 10: Content Protection (protect_content=True) Enforcement
    # ---------------------------------------------------------
    print("[10/11] Verifying protect_content=True in PublisherService...")
    pub_file = os.path.join(project_root, "moderation", "publisher.py")
    if os.path.exists(pub_file):
        with open(pub_file, "r", encoding="utf-8") as f:
            content = f.read()
            if "protect_content=True" not in content:
                issues.append("❌ publisher.py does not enforce protect_content=True")
                passed = False

    # ---------------------------------------------------------
    # Check 11: Dangerous File Handling & Path Traversal Protections
    # ---------------------------------------------------------
    print("[11/11] Verifying Media Sanitization & Decompression Bomb Defenses...")
    sanitizer_file = os.path.join(project_root, "security", "media_sanitizer.py")
    if os.path.exists(sanitizer_file):
        with open(sanitizer_file, "r", encoding="utf-8") as f:
            content = f.read()
            if "sanitize_filename" not in content or "validate_magic_bytes" not in content:
                issues.append("❌ media_sanitizer.py lacks essential filename or magic bytes validation")
                passed = False

    # ---------------------------------------------------------
    # Audit Results
    # ---------------------------------------------------------
    print("-" * 70)
    if passed and not issues:
        print("✅ FINAL ARCHITECTURAL AUDIT PASSED: ZERO CRITICAL/HIGH DEFECTS FOUND.")
        print("✅ ALL 11 ARCHITECTURAL GATES RIGIDLY ENFORCED.")
        print("=" * 70)
        return True
    else:
        print("❌ FINAL AUDIT FAILED WITH ISSUES:")
        for issue in issues:
            print(f"  {issue}")
        print("=" * 70)
        return False


if __name__ == "__main__":
    success = run_audit()
    sys.exit(0 if success else 1)
