# 🛡️ Security & Privacy Architecture Policy

## 1. Cryptographic Principles & Key Separation

The **Telegram Anonymous Student Discussion Bot** implements a privacy-first security model where Personally Identifiable Information (PII) is isolated from application logic, database queries, and logs.

```
                           +------------------------+
                           |  Master ENCRYPTION_KEY |
                           +-----------+------------+
                                       |
                   +-------------------+-------------------+
                   | (HKDF SHA-256)                        | (HKDF SHA-256)
                   v                                       v
        +----------------------+                +----------------------+
        |      Fernet Key      |                |    HMAC Blind Index  |
        |   (AES-128-CBC +     |                |       Key            |
        |    HMAC-SHA256)      |                +----------+-----------+
        +----------+-----------+                           |
                   |                                       v
                   v                            [ HMAC-SHA256 Hash ]
         [ Encrypted PII ]                      - Fast indexing & lookup
         - enc_telegram_id                      - Zero information leakage
         - enc_full_name                        - Resistant to rainbow tables
         - enc_username
```

### 1.1 HKDF Key Derivation
- Master key is never used directly for raw encryption.
- **HMAC-based Key Derivation Function (HKDF)** with SHA-256 derives domain-separated keys for symmetric encryption and deterministic blind indexing.
- Key separation prevents cross-purpose cryptographic attacks.

---

## 2. Identity Isolation Barrier & IdentityVault

All PII fields (`enc_telegram_id`, `enc_full_name`, `enc_username`) are encrypted at rest.

### Access Rules:
1. **Database Queries:** Repositories always instantiate `StudentModel` with `dec_telegram_id=None`, `dec_full_name=None`, and `dec_username=None`.
2. **Decryption Gateway:** Decryption of student identity is strictly encapsulated within `IdentityVault.resolve_student_identity()`.
3. **RBAC Isolation:**
   - **Primary Admin (`PRIMARY_ADMIN`):** Allowed to resolve student identities for safety/investigative purposes with mandatory audit logging.
   - **Moderators (`MODERATOR`):** **STRICTLY BLOCKED** from identity resolution, WHOIS lookups, and identity wipes. Can only moderate by `anonymous_id` or channel message ID.
   - **Students / Unauthorized Users:** **STRICTLY BLOCKED** with `PermissionError`.

---

## 3. Administrator Authentication & Brute-Force Lockout

- **Hashing Algorithm:** `scrypt` ($N=16384, r=8, p=1$) with 16-byte cryptographically secure random salt.
- **Constant-Time Verification:** `hmac.compare_digest` prevents timing side-channel attacks.
- **Brute-Force Lockout:**
  - Failed attempts tracked persistently per Telegram ID in PostgreSQL (`admin_login_attempts`).
  - Threshold: 5 failed attempts within 15 minutes triggers a 15-minute complete lockout.
- **Fail-Fast Startup:** Production configuration strictly mandates `ADMIN_PASSWORD_HASH`. Insecure default passwords trigger immediate application termination on startup.

---

## 4. Fail-Closed Moderation Architecture

The moderation engine operates on a strict **Fail-Closed** paradigm:
- **No Signal != Safe:** In Strict Mode, content is only permitted if all relevant analyzers finish with clean signals (`SAFE + FULLY_ANALYZED`).
- **Dependencies Down:** If OCR (`tesseract`), ASR, or document parsers crash or time out, the system defaults to `BLOCK/REVIEW` with `MEDIA_UNSAFE`.
- **Unknown Binaries:** Files without matching whitelist magic bytes or recognized extensions are blocked immediately.

---

## 5. Media Sanitization & Anti-Exploit Measures

| Threat Vector | Mitigation Strategy |
|---|---|
| **EXIF / GPS Leakage** | All photos and images are cleanly decoded, stripped of metadata/GPS tags, and re-encoded using Pillow. |
| **Path Traversal (`../`)** | User filenames are stripped of all directory separators and replaced with UUIDs. Original filenames are encrypted before storage. |
| **Decompression Bombs** | Max uncompressed size limit (50MB) and max expansion ratio (100x) enforced on all archives. Max image dimensions (10,000 x 10,000 px). |
| **Executable Masquerading** | Rejection of PE (`MZ`), ELF (`\x7fELF`), Mach-O, Java classfiles, and Shell scripts (`#!`) regardless of user-provided extension. |
| **Office Macro Exploits** | Reject any document containing `vbaProject.bin`, `.xlsm`, or `.pptm`. |

---

## 6. Channel Publication Boundary & Content Protection

1. **Single Publication Gateway:** Handlers never send content directly to Telegram channels. All messages, photos, documents, and media pass exclusively through `PublisherService.publish_post()`.
2. **Forwarding & Screen-Capture Protection:** All channel broadcasts enforce `protect_content=True`, preventing students from saving, forwarding, or leaking message originators.
3. **HTML Injection Prevention:** User text and captions are sanitized using `html.escape()` before being interpolated into channel formatting strings.

---

## 7. Logging Sanitization & Zero-PII Policy

All logging is routed through `utils/logger.py` with custom regex filters:
- **Telegram Bot Tokens:** Automatically redacted (`<REDACTED_BOT_TOKEN>`).
- **Cryptographic Keys & Hashes:** Redacted (`<REDACTED_SECRET>`).
- **User Telegram IDs (8-10 digits):** Automatically masked (`<REDACTED_USER_ID>`).
