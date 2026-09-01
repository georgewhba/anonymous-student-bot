# 🚀 Production Deployment & Operations Guide

## 1. Prerequisites

- **Python:** 3.10, 3.11, 3.12, or 3.13
- **Database:** PostgreSQL 14+ (16+ recommended)
- **External Dependencies:**
  - `tesseract-ocr` and Arabic language pack `tesseract-ocr-ara` (for image OCR moderation)
  - `ffmpeg` (for voice/audio duration inspection and keyframe sampling)
  - `libmagic` (for MIME and magic bytes inspection)

### Ubuntu / Debian Dependency Installation:
```bash
sudo apt-get update && sudo apt-get install -y \
    python3-pip \
    python3-venv \
    postgresql \
    postgresql-contrib \
    tesseract-ocr \
    tesseract-ocr-ara \
    ffmpeg \
    libmagic1
```

---

## 2. PostgreSQL Setup

Create a dedicated database user and production database:

```sql
-- Connect to PostgreSQL as superuser
sudo -u postgres psql

-- Create user and database
CREATE USER anonbot_user WITH PASSWORD 'UltraSecurePassword2026!';
CREATE DATABASE anonymous_bot OWNER anonbot_user;
GRANT ALL PRIVILEGES ON DATABASE anonymous_bot TO anonbot_user;
\q
```

---

## 3. Application Setup

1. **Clone the repository:**
   ```bash
   git clone <repository_url> /opt/anonymous-student-bot
   cd /opt/anonymous-student-bot
   ```

2. **Create virtual environment and install dependencies:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Generate Master Encryption Key & Admin Password Hash:**
   ```bash
   # Generate 32-byte URL-safe base64 encryption key
   python3 utils/key_generator.py

   # Generate secure scrypt hash for the master admin password
   python3 utils/hash_password.py "YourStrongAdminPasswordHere"
   ```

4. **Configure `.env`:**
   ```bash
   cp .env.example .env
   nano .env
   ```
   Fill in:
   - `BOT_TOKEN`
   - `CHANNEL_ID`
   - `PRIMARY_ADMIN_ID`
   - `ADMIN_PASSWORD_HASH`
   - `ENCRYPTION_KEY`
   - `DATABASE_URL=postgresql://anonbot_user:UltraSecurePassword2026!@localhost:5432/anonymous_bot`

5. **Run Alembic Migrations:**
   ```bash
   alembic upgrade head
   ```

6. **Execute Final Acceptance Gate Check:**
   ```bash
   python3 tools/run_all_checks.py
   ```

---

## 4. Systemd Service Configuration (Linux Production)

Create `/etc/systemd/system/anonymous-bot.service`:

```ini
[Unit]
Description=Telegram Anonymous Student Discussion Bot
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/anonymous-student-bot
EnvironmentFile=/opt/anonymous-student-bot/.env
ExecStart=/opt/anonymous-student-bot/venv/bin/python main.py
Restart=always
RestartSec=5s

# Security Hardening
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable anonymous-bot
sudo systemctl start anonymous-bot
sudo systemctl status anonymous-bot
```

---

## 5. Docker Deployment

### `Dockerfile`:
```dockerfile
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-ara \
    ffmpeg \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py"]
```

### `docker-compose.yml`:
```yaml
version: '3.8'

services:
  db:
    image: postgres:16-alpine
    restart: always
    environment:
      POSTGRES_DB: anonymous_bot
      POSTGRES_USER: anonbot_user
      POSTGRES_PASSWORD: DB_SECURE_PASSWORD
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U anonbot_user -d anonymous_bot"]
      interval: 5s
      timeout: 5s
      retries: 5

  bot:
    build: .
    restart: always
    env_file: .env
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - ./media_tmp:/app/media_tmp

volumes:
  pgdata:
```

---

## 6. Railway Cloud Deployment

Railway provides built-in PostgreSQL databases and native Dockerfile support:

1. Connect your repository to **Railway.app**.
2. Click **+ Create** -> **Database** -> **Add PostgreSQL**.
3. Click **+ Create** -> **GitHub Repo** -> Select `anonymous-student-bot`.
4. In the bot service's **Variables** tab, set:
   - `BOT_TOKEN`
   - `CHANNEL_ID`
   - `PRIMARY_ADMIN_ID`
   - `ENCRYPTION_KEY`
   - `ADMIN_PASSWORD_HASH`
   - `DATABASE_URL` = `${{Postgres.DATABASE_URL}}`
   - `ENABLE_PROFANITY_FILTER` = `true`
   - `OCR_ENABLED` = `true`
5. Railway will automatically build the Dockerfile, apply migrations (`alembic upgrade head`), and start the bot 24/7.
6. Detailed step-by-step instructions available in [RAILWAY_DEPLOY_GUIDE.md](file:///c:/Users/georg/.gemini/antigravity-ide/scratch/anonymous-student-bot/RAILWAY_DEPLOY_GUIDE.md).

---

## 7. Migration from Legacy SQLite

To migrate legacy data from a historical SQLite file:

```bash
python3 tools/migrate_sqlite_to_postgres.py --sqlite-path data/legacy_bot.db --pg-url postgresql://anonbot_user:password@localhost:5432/anonymous_bot
```
