# 🐘 PostgreSQL Production Database Architecture & Operations

## 1. Overview & Architecture

The **Anonymous Student Bot** operates on an enterprise-grade **PostgreSQL** relational database system designed for high concurrency, absolute data integrity, zero-PII leak prevention, and zero regressions.

```
+-------------------------------------------------------------------------+
|                           Telegram Bot Application                      |
| (Aiogram Handlers, Middleware, Publisher, Moderation Engine, Admin)     |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                       DatabaseManager (Facade)                          |
+-------------------------------------------------------------------------+
                                    |
        +---------------------------+---------------------------+
        |                           |                           |
        v                           v                           v
+------------------+       +------------------+       +------------------+
| StudentRepository|       |  PostRepository  |       | ReplyRepository  |
+------------------+       +------------------+       +------------------+
| QuotaRepository  |       | AuditRepository  |       | SettingsRepo     |
+------------------+       +------------------+       +------------------+
| AdminRepository  |
+------------------+
        |                           |                           |
        +---------------------------+---------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  DatabasePool (asyncpg Connection Pool)                |
| - Min Connections: 2                                                    |
| - Max Connections: 10 (Scalable to 50)                                 |
| - SSL / TLS Verification                                                |
| - Automatic Ping / Latency Healthcheck                                  |
| - Transaction Context Managers & Row-level Locking                      |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                         PostgreSQL 16+ Engine                           |
+-------------------------------------------------------------------------+
```

---

## 2. Relational Schema & Table Definitions

### 2.1 `students`
Stores anonymous student profiles. PII fields (`enc_telegram_id`, `enc_full_name`, `enc_username`) are encrypted via AES-128-CBC + HMAC-SHA256 (Fernet) with keys derived via HKDF.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `BIGSERIAL` | `PRIMARY KEY` | Internal row surrogate key |
| `anonymous_id` | `BIGINT` | `UNIQUE NOT NULL` | Monotonically allocated student ID (starts at 101) |
| `user_hash` | `VARCHAR(64)` | `UNIQUE NOT NULL` | Blind HMAC-SHA256 hash of Telegram ID |
| `enc_telegram_id` | `TEXT` | `NOT NULL` | Encrypted Telegram ID |
| `enc_full_name` | `TEXT` | `NULL` | Encrypted full name |
| `enc_username` | `TEXT` | `NULL` | Encrypted Telegram username |
| `is_banned` | `BOOLEAN` | `NOT NULL DEFAULT FALSE` | Permanent ban flag |
| `ban_reason` | `TEXT` | `NULL` | Reason for administrative ban |
| `muted_until` | `TIMESTAMPTZ` | `NULL` | Temporary mute expiration timestamp |
| `total_posts` | `INTEGER` | `NOT NULL DEFAULT 0` | Lifetime published posts counter |
| `total_replies` | `INTEGER` | `NOT NULL DEFAULT 0` | Lifetime published replies counter |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL DEFAULT NOW()` | Registration timestamp |
| `last_active_at` | `TIMESTAMPTZ` | `NOT NULL DEFAULT NOW()` | Last activity timestamp |

**Indexes:**
- `CREATE UNIQUE INDEX idx_students_anonymous_id ON students(anonymous_id);`
- `CREATE UNIQUE INDEX idx_students_user_hash ON students(user_hash);`
- `CREATE INDEX idx_students_is_banned ON students(is_banned);`

---

### 2.2 `banned_fingerprints`
Guarantees persistent ban enforcement across GDPR privacy wipes (`/forget_me`).

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `BIGSERIAL` | `PRIMARY KEY` | Internal row key |
| `user_hash` | `VARCHAR(64)` | `UNIQUE NOT NULL` | Blind HMAC-SHA256 hash of banned user |
| `ban_reason` | `TEXT` | `NULL` | Reason recorded during ban |
| `banned_at` | `TIMESTAMPTZ` | `NOT NULL DEFAULT NOW()` | Ban timestamp |

---

### 2.3 `posts`
Stores channel root posts submitted by anonymous students.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `BIGSERIAL` | `PRIMARY KEY` | Internal post ID |
| `anonymous_id` | `BIGINT` | `NOT NULL REFERENCES students(anonymous_id)` | Author's anonymous ID |
| `channel_message_id` | `BIGINT` | `UNIQUE NOT NULL` | Telegram message ID in the private channel |
| `user_msg_id` | `BIGINT` | `NOT NULL` | Original Telegram DM message ID |
| `media_type` | `VARCHAR(32)` | `NOT NULL` | `text`, `photo`, `document`, `voice`, etc. |
| `media_file_id` | `TEXT` | `NULL` | Telegram file ID |
| `content_preview` | `VARCHAR(500)` | `NOT NULL` | Safe textual preview for admin inspection |
| `content_hash` | `VARCHAR(64)` | `NULL` | SHA-256 duplicate content detection hash |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL DEFAULT NOW()` | Publication timestamp |
| `is_deleted` | `BOOLEAN` | `NOT NULL DEFAULT FALSE` | Soft-deletion flag |
| `enc_original_filename` | `TEXT` | `NULL` | Encrypted original document filename |
| `status` | `VARCHAR(32)` | `NOT NULL DEFAULT 'published'` | `pending`, `published`, `failed` |

**Indexes:**
- `CREATE INDEX idx_posts_anonymous_id ON posts(anonymous_id);`
- `CREATE UNIQUE INDEX idx_posts_channel_msg_id ON posts(channel_message_id);`
- `CREATE INDEX idx_posts_content_hash ON posts(content_hash);`
- `CREATE INDEX idx_posts_created_at ON posts(created_at);`

---

### 2.4 `replies`
Stores replies to channel posts.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `BIGSERIAL` | `PRIMARY KEY` | Internal reply ID |
| `parent_channel_msg_id` | `BIGINT` | `NOT NULL` | Root post Telegram channel message ID |
| `reply_channel_msg_id` | `BIGINT` | `UNIQUE NOT NULL` | Reply Telegram channel message ID |
| `anonymous_id` | `BIGINT` | `NOT NULL REFERENCES students(anonymous_id)` | Author's anonymous ID |
| `media_type` | `VARCHAR(32)` | `NOT NULL` | `text`, `photo`, `document`, etc. |
| `media_file_id` | `TEXT` | `NULL` | Telegram file ID |
| `content_preview` | `VARCHAR(500)` | `NOT NULL` | Content preview |
| `content_hash` | `VARCHAR(64)` | `NULL` | SHA-256 hash |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL DEFAULT NOW()` | Publication timestamp |
| `is_deleted` | `BOOLEAN` | `NOT NULL DEFAULT FALSE` | Soft-deletion flag |
| `enc_original_filename` | `TEXT` | `NULL` | Encrypted original filename |
| `status` | `VARCHAR(32)` | `NOT NULL DEFAULT 'published'` | `pending`, `published`, `failed` |

**Indexes:**
- `CREATE INDEX idx_replies_parent_msg ON replies(parent_channel_msg_id);`
- `CREATE UNIQUE INDEX idx_replies_reply_msg ON replies(reply_channel_msg_id);`
- `CREATE INDEX idx_replies_anonymous_id ON replies(anonymous_id);`
- `CREATE INDEX idx_replies_parent_reply_combo ON replies(parent_channel_msg_id, reply_channel_msg_id);`

---

### 2.5 `hourly_quotas`
Atomic, concurrency-safe sliding-window rate limiting.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `BIGSERIAL` | `PRIMARY KEY` | Row surrogate key |
| `user_id` | `BIGINT` | `NOT NULL` | Telegram user ID |
| `window_start` | `TIMESTAMPTZ` | `NOT NULL` | Top-of-the-hour timestamp |
| `post_count` | `INTEGER` | `NOT NULL DEFAULT 1` | Submissions counter for this window |

**Constraint & Index:**
- `UNIQUE(user_id, window_start)`
- `CREATE INDEX idx_hourly_quotas_user_window ON hourly_quotas(user_id, window_start);`

---

### 2.6 `audit_logs`
Immutable administrative audit log. Never stores raw Telegram IDs or names of non-admin targets.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `BIGSERIAL` | `PRIMARY KEY` | Audit entry ID |
| `admin_id` | `BIGINT` | `NOT NULL` | Actor admin Telegram ID |
| `action` | `VARCHAR(64)` | `NOT NULL` | `ban_student`, `unmute`, `whois_lookup`, etc. |
| `target_anonymous_id` | `BIGINT` | `NULL` | Anonymous ID of target |
| `details` | `TEXT` | `NULL` | Safe action details |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL DEFAULT NOW()` | Log timestamp |

---

### 2.7 `admin_credentials` & `admin_sessions`
Production administrator authentication, per-admin scrypt hashes, and persistent sessions.

- `admin_credentials(telegram_id PK, password_hash, role, created_at, last_login_at)`
- `admin_sessions(user_id PK, authenticated_at, role)`
- `security_events(id PK, user_id, event_type, created_at)`
- `admin_login_attempts(id PK, user_id, attempted_at)`

---

## 3. Atomic Monotonic Anonymous ID Allocation

Student IDs are guaranteed to be unique and strictly sequential without race conditions:

```sql
-- PostgreSQL Sequence created at schema initialization
CREATE SEQUENCE IF NOT EXISTS anonymous_student_id_seq START WITH 101 INCREMENT BY 1;
```

When registering a student:
```python
# Atomic allocation via nextval() within an acquired connection
next_anon_id = await conn.fetchval("SELECT nextval('anonymous_student_id_seq');")
```

---

## 4. Concurrency-Safe Rate Limiting & Row-Level Locking

The sliding hourly quota employs row-level `FOR UPDATE` or `ON CONFLICT` atomic upserts:

```sql
INSERT INTO hourly_quotas (user_id, window_start, post_count)
VALUES ($1, $2, 1)
ON CONFLICT (user_id, window_start)
DO UPDATE SET post_count = hourly_quotas.post_count + 1
RETURNING post_count;
```

If `post_count > max_quota`, the repository rolls back and rejects the submission with `(allowed=False)`.

---

## 5. Alembic Migrations

Migrations are located in `migrations/` and configured via `alembic.ini`.

### Upgrade to latest schema:
```bash
alembic upgrade head
```

### Rollback one migration:
```bash
alembic downgrade -1
```

### Generate a new revision:
```bash
alembic revision -m "add_new_feature_table"
```

---

## 6. Connection Pool Configuration & Sizing

In `.env` or production environment variables:

```ini
# PostgreSQL Connection URL
DATABASE_URL=postgresql://bot_user:StrongPassword2026@localhost:5432/anonymous_bot

# Pool Sizing
DATABASE_POOL_MIN=2
DATABASE_POOL_MAX=10

# Timeouts & Security
DATABASE_CONNECT_TIMEOUT=10.0
DATABASE_COMMAND_TIMEOUT=15.0
DATABASE_SSL_MODE=prefer
```

### Sizing Guidance:
- **Low Traffic (< 1,000 daily active students):** `MIN=2, MAX=5`
- **Medium Traffic (1,000 - 10,000 active students):** `MIN=5, MAX=15`
- **High Traffic (> 10,000 active students):** `MIN=10, MAX=30`
