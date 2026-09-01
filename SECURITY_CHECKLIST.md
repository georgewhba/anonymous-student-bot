# 🔒 Anonymous Student Bot - Security & Hardening Checklist

> **قائمة التحقق الأمني والفحص المعماري لبيئة الإنتاج (Production Security Audit)**

---

## 1. حماية الهوية والخصوصية (Identity & Privacy Isolation)
- [x] **Zero Plaintext PII at Rest:** جميع بيانات الطلاب الحساسة (`telegram_id`, `full_name`, `username`) مشفرة بالكامل في قاعدة البيانات بخوارزمية AES-128-CBC + HMAC-SHA256 (Fernet).
- [x] **HMAC Blind Indexing:** استخدام مفتاح فريد لإنشاء فهارس عمياء تمنع ربط الحسابات وتتيح البحث الفوري دون فك التشفير.
- [x] **Race-Condition Free Anonymous ID:** تخصيص الأرقام المجهولة (`101, 102...`) عبر جدول ذرّي `id_sequences` وقفل متزامن يمنع التصادمات نهائياً.
- [x] **No Forwarding Metadata:** منع استخدام توجيه الرسائل التلقائي الذي قد يسرب مصدر الرسالة، وبناء رسائل جديدة كلياً عبر البوت.
- [x] **GDPR Right to Be Forgotten:** دعم التطهير الفوري لكافة البيانات الشخصية للطالب عبر `/forget_me` و `/wipe_student`.

---

## 2. التحكم في الصلاحيات والمصادقة (Authentication & Strict RBAC)
- [x] **Strict Role Separation:** حصر كشف الهوية المشفرة (`WHOIS`)، وتطهير الحسابات (`wipe_student`)، والإذاعة (`broadcast`)، والمراسلة الخاصة (`dm`) في يد المسؤول الأساسي (`PRIMARY_ADMIN`) حصراً.
- [x] **Server-Side Enforcement:** تطبيق فحص الصلاحيات داخل منطق المعالجات وخزنة الهوية وليس فقط على واجهات الأزرار.
- [x] **Scrypt Password Hashing:** حظر كلمات المرور الصريحة واستخدام Scrypt مع 16-byte salt ومقارنة بزمن ثابت لمنع هجمات التوقيت.
- [x] **Brute-Force Shield:** إقفال حساب المشرف تلقائياً لمدة 15 دقيقة بعد 5 محاولات إدخال خاطئة.
- [x] **Memory-Only Ephemeral Sessions:** إدارة جلسات المشرفين في الذاكرة مع انتهاء تلقائي وإمكانية تسجيل الخروج الفوري.
- [x] **Telegram Chat Shoulder-Surfing Prevention:** حذف رسالة كلمة المرور فور كتابتها في المحادثة.

---

## 3. تطهير الوسائط والملفات (Media & File Sanitization)
- [x] **EXIF / GPS Stripping:** تجريد كامل لبيانات الكاميرا والموقع الجغرافي والوقت من الصور عبر Pillow.
- [x] **Magic Bytes Verification:** مطابقة البايتات الثنائية لترويسة الملفات لمنع رفع ملفات تنفيذية متخفية في هيئة مستندات.
- [x] **Path Traversal Shield:** تنقية كاملة لأسماء الملفات المرفوعة وحظر الرموز الخاصة والمسارات النسبية (`../`).
- [x] **Dangerous Extensions Blacklist:** حظر رفع أو إعادة تسمية الملفات بامتدادات تنفيذية (`.exe`, `.sh`, `.bat`, `.cmd`, `.py`, `.js`).
- [x] **Decompression Bomb Protection:** رفض الصور الضخمة التي تتجاوز أبعادها 8192 بكسل لمنع استنزاف ذاكرة الخادم (DoS).
- [x] **Guaranteed Cleanup:** حذف جميع الملفات المؤقتة من مجلد `media_tmp/` داخل كتل `finally`.

---

## 4. حماية القناة والمحتوى (Channel & Content Protection)
- [x] **Content Protection Enabled:** تفعيل `protect_content=True` على كافة رسائل القناة لمنع التحويل أو الحفظ أو التصوير.
- [x] **Strict HTML Escaping:** تشفير وتطهير كافة مدخلات الطلاب لمنع هجمات حقن وسوم HTML.
- [x] **Startup Channel Verification:** فحص استباقي للوصول للقناة وصلاحيات النشر والحذف والتنبيه من مجموعات النقاشات المرتبطة.
- [x] **Late Revalidation:** إعادة فحص عضوية الطالب وحالة الحظر والكتم وحالة النظام عند إرسال الردود.

---

## 5. منع الإغراق وسجلات الأمان (DDoS Shield & Secure Logging)
- [x] **Persistent Hourly Quotas:** تطبيق حصص ساعية مستمرة عبر قاعدة البيانات لا تتأثر بإعادة تشغيل الخادم.
- [x] **Flood & Burst Protection:** درع مكافحة الرشقات السريعة وتكرار الرسائل في الثواني المعدودة.
- [x] **Duplicate Content Detection:** كشف ومنع تكرار نفس السؤال أو الرد خلال 5 دقائق.
- [x] **Automated PII Log Scrubbing:** حجب التوكنات، مفاتيح التشفير، وكلمات المرور تلقائياً من مخرجات السجلات.
