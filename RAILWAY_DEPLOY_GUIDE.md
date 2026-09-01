# 🚆 دليل رفع وتشغيل البوت على منصة Railway خطوة بخطوة

> **دليل عملي مصور خطوة بخطوة لنشر البوت مع قاعدة بيانات PostgreSQL بنقرات بسيطة على منصة Railway**

---

## 🌟 لماذا Railway؟
- توفر **PostgreSQL مجانية/سريعة** داخل نفس المشروع بضغطة زر.
- تدعم تشغيل الـ **Dockerfile** بالكامل مع دعم حزم الـ OCR (`tesseract`) والـ `ffmpeg`.
- تقوم بتطبيق الترحيلات البرمجية (`alembic upgrade head`) وتوليد الجداول تلقائياً عند الإقلاع.
- خوادم مستقرة 24/7 وإعادة تشغيل ذاتية فورية في حال حدوث أي خطأ.

---

## 🟢 الخطوة 1: التسجيل وربط حساب GitHub في Railway

1. ادخل إلى موقع **[Railway.app](https://railway.com/)** أو **[railway.app](https://railway.app)**.
2. اضغط على **Login** أو **Start a New Project**.
3. اختر تسجيل الدخول عبر **GitHub** (`Login with GitHub`).

---

## 🟢 الخطوة 2: إنشاء مشروع جديد (New Project)

1. في لوحة التحكم الرئيسية (Dashboard)، اضغط على زر **"+ New Project"**.
2. ستظهر لك قائمة خيارات، سنقوم بإضافة **خدمتين (Two Services)** داخل هذا المشروع:
   - **الخدمة الأولى:** قاعدة بيانات PostgreSQL.
   - **الخدمة الثانية:** البوت المرتبط بمستودعك على GitHub.

---

## 🟢 الخطوة 3: إضافة قاعدة بيانات PostgreSQL (بنقرة واحدة)

1. من قائمة "+ New Project" أو بالضغط على زر **"+ Create"** داخل المشروع:
2. اختر **"Database"** $\to$ ثم اختر **"Add PostgreSQL"**.
3. ستنشئ Railway قاعدة بيانات PostgreSQL متكاملة خلال ثوانٍ معدودة.
4. اضغط على كارت **Postgres** الذي تم إنشاؤه:
   - اذهب إلى تبويب **Variables**.
   - ستجد متغيراً اسمه `DATABASE_URL` يحتوي على رابط الاتصال المشفر (احتفظ بهذه الصفحة مفتوحة أو سنربطه تلقائياً).

---

## 🟢 الخطوة 4: إضافة كود البوت من GitHub

1. داخل نفس المشروع في Railway، اضغط على زر **"+ Create"** في الزاوية العلوية (أو New Service).
2. اختر **"GitHub Repo"**.
3. اختر مستودع البوت الخاص بك: `georgewhba/anonymous-student-bot`.
4. ستتعرف Railway تلقائياً على ملف `Dockerfile` و `railway.json` الموجودين داخل المشروع.

---

## 🟢 الخطوة 5: ضبط متغيرات البيئة (Environment Variables)

1. اضغط على كارت **خدمة البوت** (anonymous-student-bot).
2. اذهب إلى تبويب **"Variables"**.
3. اضغط على **"Raw Editor"** أو أضف المتغيرات التالية يدوياً:

| اسم المتغير (Variable Name) | القيمة (Value) وكيفية الحصول عليها |
| :--- | :--- |
| `BOT_TOKEN` | توكن البوت الذي حصلت عليه من `@BotFather` |
| `CHANNEL_ID` | معرّف القناة الخاصة (مثل `-1001234567890`) |
| `PRIMARY_ADMIN_ID` | معرّف حسابك الشخصي على تيليجرام (يمكن معرفته عبر `@userinfobot`) |
| `ENCRYPTION_KEY` | مفتاح تشفير البيانات (استخرجه بتشغيل `python utils/key_generator.py`) |
| `ADMIN_PASSWORD_HASH` | تجزئة كلمة مرور الإدارة (استخرجها بتشغيل `python utils/hash_password.py "كلمة_المرور"`) |
| `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` *(أو انسخ الرابط من خدمة Postgres في خطوة 3)* |
| `DATABASE_POOL_MIN` | `1` |
| `DATABASE_POOL_MAX` | `10` |
| `ENABLE_PROFANITY_FILTER` | `true` |
| `OCR_ENABLED` | `true` |
| `FAIL_CLOSED_ON_MEDIA_ANALYSIS_ERROR` | `true` |

> 💡 **ملاحظة ذكية في Railway:** عند كتابة `${{Postgres.DATABASE_URL}}` في خانة `DATABASE_URL`، تقوم Railway بربط البوت بقاعدة البيانات تلقائياً دون الحاجة لكتابة كلمات المرور يدوياً!

---

## 🟢 الخطوة 6: البناء والتشغيل (Deploy)

1. بعد حفظ المتغيرات، ستبدأ Railway تلقائياً بعملية البناء (`Deploy`).
2. يمكنك متابعة السجلات بالضغط على تبويب **"Deployments"** ثم **"View Logs"**.
3. ستلاحظ في السجلات:
   - تثبيت حزم النظام: Python 3.12, Tesseract OCR (مع دعم اللغة العربية), FFmpeg.
   - تطبيق ترحيلات الجداول بنجاح: `Running migrations: alembic upgrade head -> OK`.
   - انطلاق البوت: `🚀 Starting Telegram Anonymous Bot (Aiogram 3.x)... Polling mode active`.

---

## 🛡️ الخطوة 7: التجربة على تيليجرام

1. تأكد من إضافة البوت **مشرفاً (Admin)** في قناتك الخاصة ومنحه صلاحية نشر الرسائل (`Post Messages`) وحذف الرسائل (`Delete Messages`).
2. افتح محادثة البوت في الخاص واضغط `/start`.
3. اكتب `/admin` لتسجيل الدخول بكلمة المرور واختبار لوحة الإدارة.
4. أرسل سؤالاً مجهولاً كطالب للتأكد من نشره في القناة بهوية مجهولة (`طالب #101`).

---

## 🔧 حل أي مشاكل محتملة (Troubleshooting)

- **س: البوت يعطي خطأ `CrashBackOff` أو يفشل في الإقلاع؟**
  - **ج:** تأكد من إدخال المتغيرات الإلزامية الثلاثة: `BOT_TOKEN`, `CHANNEL_ID`, `ENCRYPTION_KEY`, `ADMIN_PASSWORD_HASH`.
- **س: كيف أعيد تشغيل البوت أو تحديثه؟**
  - **ج:** بمجرد عمل `git push` لأي تعديل على مستودع GitHub، ستقوم Railway بإعادة البناء والتحديث تلقائياً دون أي تدخل منك (Auto Deploy).
