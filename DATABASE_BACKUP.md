# 🛡️ PostgreSQL Backup, Disaster Recovery & High Availability Runbook

## 1. Overview

This runbook specifies the production procedures for backing up, verifying, and recovering the **Anonymous Student Bot** PostgreSQL database.

---

## 2. Automated Daily Backup via `pg_dump` & Cron

### 2.1 Backup Script (`/usr/local/bin/backup_bot_db.sh`)

Create `/usr/local/bin/backup_bot_db.sh` on the server:

```bash
#!/bin/bash
set -euo pipefail

# Configuration
BACKUP_DIR="/var/backups/anonymous_bot"
DB_NAME="anonymous_bot"
DB_USER="bot_user"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/db_backup_${TIMESTAMP}.dump"
RETENTION_DAYS=30

# Ensure directory exists
mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

echo "[$(date)] Starting PostgreSQL backup for ${DB_NAME}..."

# Execute pg_dump in Custom format (compressed and allows parallel restore)
pg_dump -U "${DB_USER}" -F c -b -v -f "${BACKUP_FILE}" "${DB_NAME}"

echo "[$(date)] Backup completed successfully: ${BACKUP_FILE} ($(du -sh ${BACKUP_FILE} | cut -f1))"

# Retention policy: remove backups older than 30 days
echo "[$(date)] Cleaning up backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -type f -name "db_backup_*.dump" -mtime +${RETENTION_DAYS} -exec rm -f {} \;

echo "[$(date)] Backup and retention cycle finished."
```

Make it executable:
```bash
chmod +x /usr/local/bin/backup_bot_db.sh
```

### 2.2 Cron Job Configuration

Run `crontab -e` and configure daily automated backups at 03:00 AM server time:

```cron
# Daily PostgreSQL Backup for Anonymous Student Bot at 3:00 AM
0 3 * * * /usr/local/bin/backup_bot_db.sh >> /var/log/bot_db_backup.log 2>&1
```

---

## 3. Disaster Recovery & Restore Procedure

### 3.1 Scenario A: Restoring from a Custom Dump (`.dump`)

1. **Stop the Bot process** to prevent active writes:
   ```bash
   sudo systemctl stop anonymous-student-bot
   # or with docker:
   docker-compose stop bot
   ```

2. **Restore using `pg_restore`:**
   ```bash
   # Terminate existing connections and drop existing objects
   pg_restore -U bot_user -d anonymous_bot --clean --if-exists -v /var/backups/anonymous_bot/db_backup_YYYYMMDD_HHMMSS.dump
   ```

3. **Verify Sequences & Table Counts:**
   ```bash
   psql -U bot_user -d anonymous_bot -c "SELECT last_value FROM anonymous_student_id_seq;"
   psql -U bot_user -d anonymous_bot -c "SELECT COUNT(*) FROM students;"
   psql -U bot_user -d anonymous_bot -c "SELECT COUNT(*) FROM posts;"
   ```

4. **Restart the Bot:**
   ```bash
   sudo systemctl start anonymous-student-bot
   # or with docker:
   docker-compose start bot
   ```

---

### 3.2 Scenario B: Disaster Recovery to a Fresh Server

1. **Install PostgreSQL 16+ & Create Database/User:**
   ```sql
   CREATE USER bot_user WITH PASSWORD 'StrongPassword2026';
   CREATE DATABASE anonymous_bot OWNER bot_user;
   GRANT ALL PRIVILEGES ON DATABASE anonymous_bot TO bot_user;
   ```

2. **Copy the backup file to the fresh server:**
   ```bash
   scp user@old-server:/var/backups/anonymous_bot/db_backup_latest.dump /tmp/
   ```

3. **Restore schema and data:**
   ```bash
   pg_restore -U bot_user -d anonymous_bot -v /tmp/db_backup_latest.dump
   ```

4. **Run Alembic to ensure migrations are in sync:**
   ```bash
   alembic upgrade head
   ```

5. **Start Bot:**
   ```bash
   python main.py
   ```

---

## 4. Periodic Backup Verification Drill (Monthly)

To ensure backups are not corrupt and recovery procedures work flawlessly, execute the automated drill once a month:

```bash
# 1. Create a test database
createdb -U postgres anonymous_bot_restore_test

# 2. Restore latest dump into test database
pg_restore -U postgres -d anonymous_bot_restore_test /var/backups/anonymous_bot/db_backup_latest.dump

# 3. Run test suite against the restored database
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/anonymous_bot_restore_test" pytest tests/test_database.py -v

# 4. Drop test database
dropdb -U postgres anonymous_bot_restore_test
```
