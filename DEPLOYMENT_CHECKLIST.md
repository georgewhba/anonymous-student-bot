# 🚀 Anonymous Student Bot - Production Deployment Checklist

> **دليل النشر والتشغيل الاحترافي على خوادم الإنتاج (Linux / VPS / Docker / Systemd)**

---

## 1. تجهيز الخادم والبيئة الأساسية (Server Preparation)

### تحديث النظام وتثبيت المتطلبات الأساسية
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git curl
```

### إنشاء مستخدم مخصص للبوت بدون صلاحيات Root
```bash
sudo useradd -m -s /bin/bash botuser
sudo su - botuser
```

---

## 2. إعداد المشروع والبيئة الافتراضية

```bash
git clone <YOUR_REPO_URL> anonymous-student-bot
cd anonymous-student-bot

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

---

## 3. توليد المفاتيح وضبط المتغيرات البيئية

### أ) توليد مفتاح التشفير العسكري
```bash
python utils/key_generator.py
```

### ب) توليد تجزئة كلمة المرور الآمنة
```bash
python utils/hash_password.py "YourStrongAdminPasswordHere"
```

### ج) إنشاء وضبط ملف `.env`
```bash
cp .env.example .env
nano .env
```
*قم بتعبئة التوكن، معرف القناة، ومعرف المسؤول الأساسي والمشرفين والمفاتيح.*

### د) تأمين أذونات ملف `.env` وقاعدة البيانات
```bash
chmod 600 .env
mkdir -p data media_tmp
chmod 700 data media_tmp
```

---

## 4. التحقق واختبار الصحة الشامل (Pre-Flight Checks)

```bash
# تشغيل كامل حزمة الاختبارات الآلية
pytest -v

# التحقق من خلو الأكواد من الأخطاء النحوية
python -m compileall -q .
```

---

## 5. التشغيل كخدمة نظام مستمرة (Systemd Service)

أنشئ ملف الخدمة:
```bash
sudo nano /etc/systemd/system/anonymous-student-bot.service
```

أضف الإعدادات التالية:
```ini
[Unit]
Description=Anonymous Student Discussion Telegram Bot
After=network.target

[Service]
Type=simple
User=botuser
WorkingDirectory=/home/botuser/anonymous-student-bot
ExecStart=/home/botuser/anonymous-student-bot/venv/bin/python main.py
Restart=always
RestartSec=10
EnvironmentFile=/home/botuser/anonymous-student-bot/.env

# قيود الأمان لبيئة التشغيل
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/home/botuser/anonymous-student-bot/data /home/botuser/anonymous-student-bot/media_tmp
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### تفعيل وتشغيل الخدمة
```bash
sudo systemctl daemon-reload
sudo systemctl enable anonymous-student-bot
sudo systemctl start anonymous-student-bot
```

### متابعة سجلات التشغيل
```bash
sudo journalctl -u anonymous-student-bot -f
```

---

## 6. إجراءات النسخ الاحتياطي (Automated Backups)

يُوصى بعمل نسخة احتياطية يومية مجدولة لقاعدة بيانات PostgreSQL المشفرة:
```bash
# سكريبت النسخ الاحتياطي لقاعدة بيانات PostgreSQL
pg_dump -U bot_user -F c -b -v -f "/var/backups/anonymous_bot/db_backup_$(date +\%Y\%m\%d_\%H\%M\%S).dump" anonymous_bot
```
للاطلاع على دليل خطة استعادة البيانات الكاملة واختبار الاسترداد، يرجى مراجعة [DATABASE_BACKUP.md](file:///c:/Users/georg/.gemini/antigravity-ide/scratch/anonymous-student-bot/DATABASE_BACKUP.md).
