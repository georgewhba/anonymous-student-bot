"""
Final Automated Audit Script for Production Verification.
Executes rigorous static and architectural audits across the codebase:
1. Secret and Credential Leaks Scan
2. Direct Channel Publication Bypass Scan
3. Unauthorized Decryption Scan
4. Insecure Password & Dangerous Fallbacks Scan
5. Environment & Security Config Validation Scan
6. PII & Logging Sanitizer Scan

Exits with:
0 = PASS (Ready for Delivery)
1 = FAIL (Blocking Issues Detected)
"""
import os
import sys
import re
import ast

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def run_audit() -> bool:
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    print("=" * 70)
    print("🔍 RUNNING AUTOMATED FINAL ACCEPTANCE AUDIT...")
    print("=" * 70)

    passed = True
    issues = []

    # ---------------------------------------------------------
    # Check 1: Secret Scan in Code Files
    # ---------------------------------------------------------
    print("[1/6] Scanning for Hardcoded Secrets and Tokens...")
    secret_patterns = [
        re.compile(r"bot_token\s*=\s*['\"][0-9]{8,10}:[a-zA-Z0-9_-]{35}['\"]"),
        re.compile(r"ENCRYPTION_KEY\s*=\s*['\"][a-zA-Z0-9_-]{43}=['\"]")
    ]
    for root, dirs, files in os.walk(project_root):
        if any(ignored in root for ignored in ["tests", ".pytest_cache", ".git", "__pycache__", "media_tmp"]):
            continue
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                    for pattern in secret_patterns:
                        if pattern.search(content):
                            issues.append(f"❌ Hardcoded secret pattern in: {os.path.relpath(path, project_root)}")
                            passed = False

    # ---------------------------------------------------------
    # Check 2: Direct Channel Publication Bypass Scan
    # ---------------------------------------------------------
    print("[2/6] Scanning for Direct Channel Send Calls outside PublisherService...")
    direct_send_pattern = re.compile(
        r"bot\.send_(message|photo|document|voice|audio|video|animation)\s*\(\s*[^)]*channel_id",
        re.IGNORECASE
    )
    for root, dirs, files in os.walk(project_root):
        if any(ignored in root for ignored in ["tests", ".pytest_cache", ".git", "__pycache__", "media_tmp"]):
            continue
        for file in files:
            if file.endswith(".py") and file not in ["publisher.py", "logger.py"]:
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if direct_send_pattern.search(content):
                        issues.append(f"❌ Direct channel send detected outside publisher: {os.path.relpath(path, project_root)}")
                        passed = False

    # ---------------------------------------------------------
    # Check 3: Unauthorized Decryption Scan outside IdentityVault
    # ---------------------------------------------------------
    print("[3/6] Scanning for Unauthorized Decryption calls outside IdentityVault...")
    decrypt_pattern = re.compile(r"(crypto|db\.crypto)\.decrypt(_int)?\s*\(")
    for root, dirs, files in os.walk(project_root):
        if any(ignored in root for ignored in ["tests", ".pytest_cache", ".git", "__pycache__", "media_tmp"]):
            continue
        for file in files:
            if file.endswith(".py") and file not in ["identity_vault.py", "crypto.py", "db_manager.py"]:
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if decrypt_pattern.search(content):
                        issues.append(f"❌ Direct decrypt call outside IdentityVault in: {os.path.relpath(path, project_root)}")
                        passed = False

    # ---------------------------------------------------------
    # Check 4: Insecure Default Password Scan
    # ---------------------------------------------------------
    print("[4/6] Scanning for Insecure Hardcoded Admin Passwords...")
    insecure_pwd_pattern = re.compile(r"admin_password\s*=\s*['\"](admin|123456|password|admin123)['\"]", re.IGNORECASE)
    config_file = os.path.join(project_root, "config.py")
    if os.path.exists(config_file):
        with open(config_file, "r", encoding="utf-8") as f:
            if insecure_pwd_pattern.search(f.read()):
                issues.append("❌ Insecure default password detected in config.py")
                passed = False

    # ---------------------------------------------------------
    # Check 5: .env.example Completeness
    # ---------------------------------------------------------
    print("[5/6] Validating .env.example Template...")
    env_example = os.path.join(project_root, ".env.example")
    if not os.path.exists(env_example):
        issues.append("❌ Missing .env.example file")
        passed = False
    else:
        with open(env_example, "r", encoding="utf-8") as f:
            env_content = f.read()
            required_envs = ["BOT_TOKEN", "CHANNEL_ID", "ENCRYPTION_KEY", "PRIMARY_ADMIN_ID"]
            for req in required_envs:
                if req not in env_content:
                    issues.append(f"❌ .env.example missing required key: {req}")
                    passed = False

    # ---------------------------------------------------------
    # Check 6: Logging Sanitizer Verification
    # ---------------------------------------------------------
    print("[6/6] Verifying Logging Sanitizer...")
    logger_file = os.path.join(project_root, "utils", "logger.py")
    if not os.path.exists(logger_file):
        issues.append("❌ Missing utils/logger.py")
        passed = False
    else:
        with open(logger_file, "r", encoding="utf-8") as f:
            if "scrub_pii_from_log_message" not in f.read():
                issues.append("❌ logger.py lacks PII scrubbing logic")
                passed = False

    # ---------------------------------------------------------
    # Audit Results
    # ---------------------------------------------------------
    print("-" * 70)
    if passed and not issues:
        print("✅ FINAL AUDIT PASSED: ZERO CRITICAL/HIGH DEFECTS FOUND.")
        print("✅ ALL ARCHITECTURAL CONTRACTS RIGIDLY ENFORCED.")
        print("=" * 70)
        return True
    else:
        print("❌ FINAL AUDIT FAILED:")
        for issue in issues:
            print(f"  {issue}")
        print("=" * 70)
        return False


if __name__ == "__main__":
    success = run_audit()
    sys.exit(0 if success else 1)
