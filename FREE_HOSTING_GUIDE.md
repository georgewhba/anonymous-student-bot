# 🚀 الدليل الشامل لرفع وتشغيل البوت مجاناً 100% مدى الحياة
> **دليل هندسي خطوة بخطوة لتشغيل بوت الطلاب المجهول مع قاعدة بيانات PostgreSQL وسيرفر يعمل 24/7 مجاناً بدون دفع أي سنت**

---

## 🎯 الهيكل المجاني المقترح (Architecture)

1. **قاعدة البيانات (PostgreSQL):** عبر منصة **[Neon.tech](https://neon.tech)** (خطة مجانية دائمة، استجابة سريعة، تشفير SSL، واستقرار تام).
2. **استضافة البوت (Compute / 24/7 Server):** يمكنك الاختيار من 3 طرق مجانية سهلة:
   - **الخيار الأول (الأسهل والأقوى):** **[Koyeb](https://www.koyeb.com)** (استضافة حاويات مجانية تدعم Polling أو Webhook بدون توقف).
   - **الخيار الثاني:** **[Render.com](https://render.com)** (استضافة سحابية بنقرة واحدة عبر GitHub و Docker).
   - **الخيار الثالث (24/7 بدون نوم إطلاقاً):** **[Hugging Face Spaces](https://huggingface.co/spaces)** (Docker Space مجاني 24/7 بمواصفات 2 vCPU و 16GB RAM).

---

## 🟢 الخطوة 1: إنشاء قاعدة بيانات PostgreSQL مجانية على Neon (دقيقتان)

1. ادخل إلى **[neon.tech](https://neon.tech)** وسجل حساباً مجانياً (Sign Up with GitHub / Google).
2. اضغط على **"Create Project"**، وسمّ المشروع مثلاً: `anonymous-bot-db`.
3. اختر أقرب منطقة لك (مثلاً `Frankfurt - eu-central-1`).
4. بعد إنشاء المشروع فوراً، ستظهر لك شاشة **Connection Details**:
   - اختر **Connection String** من القائمة.
   - ستجد رابطاً يبدأ بهذا الشكل:
     ```text
     postgresql://username:password@ep-cool-sample.eu-central-1.aws.neon.tech/neondb?sslmode=require
     ```
   - **انسخ هذا الرابط**، فهذا هو متغير `DATABASE_URL` الذي سنستخدمه.

---

## 🟢 الخطوة 2: تجهيز مفاتيح التشفير وكلمة المرور

على جهازك داخل مجلد المشروع، افتح الطرفية (Terminal) واستخرج المفاتيح:

### 1. توليد مفتاح تشفير البيانات (`ENCRYPTION_KEY`):
```bash
python utils/key_generator.py
```
*مثال للمفتاح الناتج:* `s8zPzX1w2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9=`

### 2. توليد تجزئة كلمة مرور الإدارة (`ADMIN_PASSWORD_HASH`):
```bash
python utils/hash_password.py "كلمة_مرور_قوية_جدا_هنا"
```
*مثال للتجزئة الناتجة:* `scrypt$16384$8$1$abc...`

---

## 🟢 الخطوة 3: رفع الكود على GitHub (مستودع خاص Private Repo)

1. أنشئ مستودعاً جديداً (New Repository) على **[GitHub.com](https://github.com)** واجعله **Private**.
2. ارفع كود المشروع إليه:
   ```bash
   git init
   git add .
   git commit -m "Production-grade PostgreSQL Anonymous Telegram Bot"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
   git push -u origin main
   ```

---

## 🟢 الخطوة 4: تشغيل البوت على المنصة المجانية

اختر إحدى المنصات التالية (جميعها مجانية 100%):

---

### 🌟 الخيار (أ): الرفع عبر Koyeb (موصى به بشدة)

1. سجل حساباً مجانياً على **[koyeb.com](https://www.koyeb.com)**.
2. اضغط على **"Create Service"** واختر **"GitHub"**.
3. اختر مستودع البوت الخاص بك من القائمة.
4. في إعدادات البناء (Builder):
   - اختر **Dockerfile** (سيتعرف تلقائياً على ملف `Dockerfile` المرفق في المشروع).
5. في قسم **Environment Variables (متغيرات البيئة)**، أضف المتغيرات التالية:

| اسم المتغير (Key) | القيمة (Value) |
| :--- | :--- |
| `BOT_TOKEN` | توكن البوت من BotFather |
| `CHANNEL_ID` | معرف القناة الخاصة (مثل: `-1001234567890`) |
| `PRIMARY_ADMIN_ID` | معرف حسابك التليجرام الشخصي (الأرقام فقط) |
| `ENCRYPTION_KEY` | المفتاح المستخرج من خطوة 2 |
| `ADMIN_PASSWORD_HASH` | تجزئة كلمة المرور من خطوة 2 |
| `DATABASE_URL` | رابط قاعدة بيانات Neon المستخرج من خطوة 1 |
| `DATABASE_POOL_MIN` | `1` |
| `DATABASE_POOL_MAX` | `5` |
| `ENABLE_PROFANITY_FILTER` | `true` |
| `OCR_ENABLED` | `true` |

6. اضغط على **"Deploy"**!
   - سيقوم الخادم ببناء المشروع، وتطبيق ترحيلات قاعدة البيانات تلقائياً (`alembic upgrade head`)، وتشغيل البوت في غضون دقيقة واحدة.

---

### 🌟 الخيار (ب): الرفع عبر Render.com

1. سجل حساباً مجانياً على **[render.com](https://render.com)**.
2. اضغط على **"New +"** ثم اختر **"Web Service"** أو **"Background Worker"**.
3. اربط مستودع GitHub الخاص بالمشروع.
4. في نوع البيئة (Environment)، اختر **Docker**.
5. اختر الخطة المجانية **Free Tier**.
6. في قسم **Environment Variables**، أضف نفس المتغيرات المذكورة في الجدول أعلاه.
7. اضغط على **"Create Web Service"**.
   - سيبدأ البوت بالعمل فوراً وسيقوم بتطبيق جداول قاعدة البيانات تلقائياً.

---

### 🌟 الخيار (ج): الرفع عبر Hugging Face Spaces (يعمل 24/7 دون نوم)

1. سجل حساباً مجانياً على **[huggingface.co](https://huggingface.co)**.
2. ادخل على **Spaces** واضغط **"Create new Space"**.
3. اختر اسماً للـ Space وحدد الترخيص.
4. في **Space SDK**، اختر **Docker** (Blank).
5. اجعل الـ Space **Private** لحماية مشروعك.
6. بعد إنشاء الـ Space، اذهب إلى تبويب **Settings** $\to$ **Variables and secrets**:
   - أضف كل متغير بيئي كـ **Secret** بنفس الأسماء المذكورة في الجدول أعلاه.
7. ارفع ملفات المشروع إلى الـ Space عبر Git.
   - سيبدأ بالعمل فوراً على مواصفات **2 CPU / 16GB RAM مجاناً مدى الحياة 24/7**.

---

## 🛡️ الخطوة 5: التحقق من تشغيل البوت في تيليجرام

1. افتح تطبيق تيليجرام وتأكد أن البوت **مشرف في القناة الخاصة** ولديه صلاحية نشر الرسائل وحذف الرسائل.
2. افتح محادثة البوت في الخاص واضغط `/start`.
3. اكتب `/admin` لتسجيل الدخول كمسؤول واختبار لوحة التحكم.
4. جرب إرسال سؤال أو صورة في الخاص كطالب وتأكد من نشرها في القناة بهوية `طالب #101` بدون أي اسم أو هوية مكشوفة.

---

## 🔧 حل المشاكل الشائعة (Troubleshooting)

- **س: البوت لا ينشر الرسائل في القناة؟**
  - **ج:** تأكد من إضافة البوت كمشرف (Administrator) في القناة الخاصة وتفعيل صلاحية `Post Messages`.
- **س: ظهر خطأ في الاتصال بقاعدة البيانات `asyncpg.exceptions`؟**
  - **ج:** تأكد من نسخ رابط Neon كاملاً بما في ذلك اسم المستخدم وكلمة المرور، وتأكد أن المتغير يسمى `DATABASE_URL`.
- **س: كيف أعرف أرقام الـ ID الخاصة بي وبالقناة؟**
  - **ج:** يمكنك إرسال أي رسالة إلى بوت `@userinfobot` أو `@ShowJsonBot` في تيليجرام لمعرفة الـ ID الخاص بك أو بقناتك.
