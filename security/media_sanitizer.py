"""
Media Sanitization Pipeline.
Performs download, MIME & magic bytes verification, EXIF/GPS metadata stripping,
filename sanitization, size/dimension validation, and secure temporary file cleanup.
"""
import io
import os
import re
import uuid
import shutil
from typing import Optional, Tuple
from PIL import Image, ImageOps
from aiogram import Bot
from aiogram.types import Message, FSInputFile
from utils.logger import logger

# الصيغ التنفيذية والخطيرة المحظورة تماماً
DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".js", ".jar",
    ".apk", ".app", ".msi", ".dll", ".sys", ".sh", ".bash", ".ps1", ".py",
    ".php", ".pl", ".cgi", ".asp", ".aspx", ".elf", ".bin", ".reg", ".deb",
    ".rpm", ".dmg", ".iso", ".img", ".vhd", ".class", ".action", ".wsf"
}

# الامتدادات الآمنة المدعومة للمستندات والوسائط
SAFE_DOCUMENT_EXTENSIONS = {
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
    ".txt", ".csv", ".zip", ".rar", ".7z", ".png", ".jpg", ".jpeg",
    ".webp", ".ogg", ".mp3", ".mp4"
}

# تواقيع الملفات التنفيذية والخطيرة للتحقق العميق
KNOWN_EXECUTABLE_SIGNATURES = [
    b"MZ",                       # DOS/Windows PE Executable / DLL
    b"\x7fELF",                  # Linux ELF Executable / Shared Object
    b"\xca\xfe\xba\xbe",         # Java Classfile / Mach-O Universal
    b"\xfe\xed\xfa\xce",         # Mach-O binary (32-bit)
    b"\xfe\xed\xfa\xcf",         # Mach-O binary (64-bit)
    b"\xce\xfa\xed\xfe",         # Mach-O binary (reverse)
    b"\xcf\xfa\xed\xfe",         # Mach-O binary (reverse 64-bit)
    b"#!",                       # Unix Script / Shebang
    b"MSCF",                     # Microsoft Cabinet File
]


class MediaSanitizer:
    """
    خط معالجة وتطهير الوسائط والملفات قبل النشر في القناة الخاصة
    """

    def __init__(self, temp_dir: str = "media_tmp", max_file_size_mb: int = 20):
        self.temp_dir = temp_dir
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        os.makedirs(self.temp_dir, exist_ok=True)

    def sanitize_filename(self, raw_filename: Optional[str]) -> str:
        """
        تطهير اسم الملف لمنع ثغرات Path Traversal والأسماء الخبيثة
        ورفض أي امتدادات خطيرة دون استبدالها بصيغ مبهمة
        """
        if not raw_filename:
            return f"document_{uuid.uuid4().hex[:8]}.pdf"

        # إزالة المسارات ومحاولات directory traversal
        filename = os.path.basename(raw_filename.replace("\\", "/"))
        # إزالة الحروف غير الآمنة والتحكم
        filename = re.sub(r'[^\w\s\.-]', '_', filename)
        # إزالة النقاط المتتالية
        filename = re.sub(r'\.{2,}', '.', filename).strip(" ._")

        name, ext = os.path.splitext(filename)
        ext_lower = ext.lower()

        if not ext_lower or ext_lower in DANGEROUS_EXTENSIONS or ext_lower not in SAFE_DOCUMENT_EXTENSIONS:
            raise ValueError(f"نوع الملف ({ext_lower or 'بدون امتداد'}) محظور أمنياً ولا يمكن قبوله.")

        if len(name) > 60:
            name = name[:60]

        return f"{name}{ext_lower}"

    def sanitize_image_bytes(self, image_data: bytes) -> bytes:
        """
        تطهير الصورة بالكامل من كافة بيانات EXIF وGPS والكاميرا
        وإعادة إنتاجها نظيفة تماماً باستخدام Pillow
        """
        with Image.open(io.BytesIO(image_data)) as img:
            # فحص أبعاد الصورة لمنع قنابل إلغاء الضغط (Decompression Bombs)
            if img.width > 8192 or img.height > 8192:
                raise ValueError("أبعاد الصورة كبيرة جداً وتتجاوز الحد الآمن المسموح.")

            # توحيد اتجاه الصورة قبل مسح EXIF
            img = ImageOps.exif_transpose(img)

            # تحويل نمط الألوان المناسب
            if img.mode in ("RGBA", "LA", "P"):
                clean_img = Image.new("RGBA", img.size)
                clean_img.paste(img)
                output = io.BytesIO()
                clean_img.save(output, format="PNG", optimize=True)
                return output.getvalue()
            else:
                clean_img = Image.new("RGB", img.size)
                clean_img.paste(img)
                output = io.BytesIO()
                clean_img.save(output, format="JPEG", quality=90, optimize=True)
                return output.getvalue()

    def validate_magic_bytes(self, header: bytes, ext: str) -> bool:
        """التحقق من تطابق البايتات السحرية مع امتداد الملف ورفض أي تواقيع تنفيذية"""
        if not header:
            return False

        # 1. التحقق من عدم وجود أي توقيع تنفيذي أو شل سكريبت
        for sig in KNOWN_EXECUTABLE_SIGNATURES:
            if header.startswith(sig):
                return False

        ext = ext.lower()
        if ext in (".jpg", ".jpeg"):
            return header.startswith(b"\xff\xd8\xff")
        if ext == ".png":
            return header.startswith(b"\x89PNG\r\n\x1a\n")
        if ext == ".pdf":
            return header.startswith(b"%PDF")
        if ext in (".docx", ".xlsx", ".pptx", ".zip"):
            return header.startswith(b"PK\x03\x04")
        if ext == ".rar":
            return header.startswith(b"Rar!\x1a\x07")
        if ext == ".7z":
            return header.startswith(b"7z\xbc\xaf'\x1c")
        if ext == ".webp":
            return header.startswith(b"RIFF") and b"WEBP" in header[:16]
        if ext == ".ogg":
            return header.startswith(b"OggS")
        if ext == ".mp3":
            return header.startswith(b"ID3") or header.startswith(b"\xff\xfb") or header.startswith(b"\xff\xf3")
        if ext == ".mp4":
            return b"ftyp" in header[4:12]
        if ext in (".txt", ".csv"):
            # الملفات النصية يجب ألا تحتوي على بايتات صفرية (Null Bytes) دالة على ملفات ثنائية
            return b"\x00" not in header[:64]

        return False

    def validate_file_security(
        self,
        file_path: str,
        expected_type: str = "document",
        original_filename: Optional[str] = None
    ) -> bool:
        """
        فحص أمني متكامل للملف على القرص:
        1. التحقق من وجود الملف وحجمه
        2. التحقق من سلامة الاسم والامتداد
        3. التحقق من البايتات السحرية وتواقيع الملفات التنفيذية
        4. فحص عميق لأرشيفات ZIP لمنع Path Traversal وقنابل الضغط
        """
        if not file_path or not os.path.exists(file_path):
            return False

        try:
            size = os.path.getsize(file_path)
            if size <= 0 or size > self.max_file_size_bytes:
                return False

            fname = original_filename or os.path.basename(file_path)
            try:
                safe_name = self.sanitize_filename(fname)
            except Exception:
                return False

            _, ext = os.path.splitext(safe_name)
            ext_lower = ext.lower()

            with open(file_path, "rb") as f:
                header = f.read(64)

            # التحقق من عدم وجود أي توقيع تنفيذي
            for sig in KNOWN_EXECUTABLE_SIGNATURES:
                if header.startswith(sig):
                    return False

            if not self.validate_magic_bytes(header, ext_lower):
                return False

            # فحص إضافي لأرشيفات ZIP
            if ext_lower == ".zip":
                import zipfile
                with zipfile.ZipFile(file_path, "r") as zf:
                    total_uncompressed = 0
                    for info in zf.infolist():
                        # فحص Path Traversal
                        if ".." in info.filename or info.filename.startswith("/") or info.filename.startswith("\\"):
                            return False
                        # فحص الامتدادات الخطيرة داخل الأرشيف
                        inner_ext = os.path.splitext(info.filename)[1].lower()
                        if inner_ext in DANGEROUS_EXTENSIONS:
                            return False
                        total_uncompressed += info.file_size
                        # حماية من قنابل ZIP (أقصى حجم 100MB فك ضغط)
                        if total_uncompressed > 100 * 1024 * 1024:
                            return False

            return True
        except Exception as e:
            logger.warning(f"فشل الفحص الأمني للملف {file_path}: {e}")
            return False

    async def download_and_sanitize(
        self,
        bot: Bot,
        file_id: str,
        media_type: str,
        original_filename: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        تنزيل الوسائط، تطهيرها، حفظها في مجلد مؤقت آمن وإرجاع مسار الملف المنظف
        يرجع: (clean_file_path, safe_display_name)
        """
        file_info = await bot.get_file(file_id)
        if file_info.file_size and file_info.file_size > self.max_file_size_bytes:
            raise ValueError(f"حجم الملف يتجاوز الحد الأقصى المسموح ({self.max_file_size_bytes // (1024*1024)}MB).")

        # تنزيل الملف إلى الذاكرة
        downloaded = await bot.download_file(file_info.file_path)
        if not downloaded:
            raise IOError("فشل تنزيل الملف من خوادم تيليجرام.")

        raw_bytes = downloaded.read() if hasattr(downloaded, "read") else downloaded

        if len(raw_bytes) > self.max_file_size_bytes:
            raise ValueError("حجم الملف المنزّل يتجاوز الحد الأقصى المسموح.")

        unique_id = uuid.uuid4().hex
        safe_filename = self.sanitize_filename(original_filename)

        if media_type == "photo":
            clean_bytes = self.sanitize_image_bytes(raw_bytes)
            clean_path = os.path.join(self.temp_dir, f"photo_{unique_id}.jpg")
            with open(clean_path, "wb") as f:
                f.write(clean_bytes)
            return clean_path, "photo.jpg"

        elif media_type == "document":
            _, ext = os.path.splitext(safe_filename)
            # فحص البايتات السحرية
            if not self.validate_magic_bytes(raw_bytes[:16], ext):
                raise ValueError("محتوى الملف لا يتطابق مع امتداده المصرح به.")

            random_doc_name = f"document_{unique_id[:8]}{ext}"
            clean_path = os.path.join(self.temp_dir, f"doc_{unique_id}_{random_doc_name}")
            with open(clean_path, "wb") as f:
                f.write(raw_bytes)
            return clean_path, random_doc_name

        else:
            # صوت أو فيديو أو تسجيل صوتي: حفظ باسم عشوائي آمن لتجريد المسارات الأصلية
            ext_map = {"voice": ".ogg", "audio": ".mp3", "video": ".mp4"}
            ext = ext_map.get(media_type, ".dat")
            clean_path = os.path.join(self.temp_dir, f"{media_type}_{unique_id}{ext}")
            with open(clean_path, "wb") as f:
                f.write(raw_bytes)
            return clean_path, f"{media_type}{ext}"

    def cleanup_file(self, file_path: Optional[str]) -> None:
        """حذف الملف المؤقت بأمان"""
        if not file_path:
            return
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            logger.warning(f"تعذر حذف الملف المؤقت {file_path}: {e}")

    def cleanup_all_temp_files(self) -> None:
        """تنظيف كامل للمجلد المؤقت عند بدء أو إيقاف التشغيل"""
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            os.makedirs(self.temp_dir, exist_ok=True)
        except Exception as e:
            logger.warning(f"تعذر مسح مجلد الملفات المؤقتة {self.temp_dir}: {e}")


# كائن المعالجة العام
media_sanitizer = MediaSanitizer()
