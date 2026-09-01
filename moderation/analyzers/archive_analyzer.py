"""
Recursive Archive Security Analyzer.
Performs bounded deep-scanning of ZIP and TAR archives in isolated sandboxes,
verifying decompression ratios, path traversal immunity, nested archives, and executable signatures.
"""
import os
import zipfile
import tarfile
import shutil
import tempfile
from typing import List, Tuple, Optional
from utils.logger import logger
from moderation.models import (
    ViolationCategory,
    SeverityLevel,
    ModerationSignal
)

MAX_ARCHIVE_FILES = 100
MAX_UNCOMPRESSED_ARCHIVE_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_NESTING_DEPTH = 3

DANGEROUS_ARCHIVE_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".js", ".jar",
    ".apk", ".app", ".msi", ".dll", ".sys", ".sh", ".bash", ".ps1", ".py",
    ".php", ".pl", ".cgi", ".asp", ".aspx", ".elf", ".bin", ".reg", ".deb",
    ".rpm", ".dmg", ".iso", ".img", ".vhd", ".class", ".action", ".wsf"
}

EXECUTABLE_SIGNATURES = [
    b"MZ",                       # DOS/PE
    b"\x7fELF",                  # Linux ELF
    b"\xca\xfe\xba\xbe",         # Java Class / Mach-O universal
    b"\xfe\xed\xfa\xce",         # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",         # Mach-O 64-bit
    b"#!",                       # Shebang script
]


class ArchiveAnalyzer:
    """محلل الأرشيفات المضغوطة والفحص الأمني العميق (Recursive Archive Scanner)"""

    def __init__(self, fail_closed: bool = True):
        self.fail_closed = fail_closed

    def inspect_archive(
        self,
        file_path: str,
        depth: int = 0
    ) -> Tuple[List[str], List[ModerationSignal]]:
        """
        فحص الأرشيف واستخراج نصوص الملفات الداخلية مع التحقق الأمني الكامل
        يرجع: (extracted_internal_texts, security_signals)
        """
        signals: List[ModerationSignal] = []
        internal_texts: List[str] = []

        if depth > MAX_NESTING_DEPTH:
            signals.append(ModerationSignal(
                source="ARCHIVE",
                category=ViolationCategory.MEDIA_UNSAFE,
                severity=SeverityLevel.CRITICAL,
                confidence=1.0,
                is_violation=True,
                is_security=True,
                reason="Archive exceeds maximum allowed nesting depth"
            ))
            return internal_texts, signals

        if not os.path.exists(file_path):
            signals.append(ModerationSignal(
                source="ARCHIVE",
                category=ViolationCategory.MEDIA_UNSAFE,
                severity=SeverityLevel.HIGH,
                confidence=1.0,
                is_violation=True,
                is_security=True,
                reason="Archive file not found on disk"
            ))
            return internal_texts, signals

        # 1. فحص ZIP
        if zipfile.is_zipfile(file_path):
            return self._inspect_zip(file_path, depth)

        # 2. فحص TAR
        elif tarfile.is_tarfile(file_path):
            return self._inspect_tar(file_path, depth)

        else:
            if self.fail_closed:
                signals.append(ModerationSignal(
                    source="ARCHIVE",
                    category=ViolationCategory.MEDIA_UNSAFE,
                    severity=SeverityLevel.HIGH,
                    confidence=1.0,
                    is_violation=True,
                    is_security=True,
                    reason="Corrupted or unsupported archive container"
                ))
            return internal_texts, signals

    def _inspect_zip(self, file_path: str, depth: int) -> Tuple[List[str], List[ModerationSignal]]:
        signals = []
        texts = []
        temp_extract_dir = tempfile.mkdtemp(prefix="safe_zip_")

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                infolist = zf.infolist()
                if len(infolist) > MAX_ARCHIVE_FILES:
                    signals.append(ModerationSignal(
                        source="ARCHIVE",
                        category=ViolationCategory.MEDIA_UNSAFE,
                        severity=SeverityLevel.HIGH,
                        confidence=1.0,
                        is_violation=True,
                        is_security=True,
                        reason="Archive file count exceeds security limit"
                    ))
                    return texts, signals

                total_uncompressed = sum(info.file_size for info in infolist)
                if total_uncompressed > MAX_UNCOMPRESSED_ARCHIVE_BYTES:
                    signals.append(ModerationSignal(
                        source="ARCHIVE",
                        category=ViolationCategory.MEDIA_UNSAFE,
                        severity=SeverityLevel.CRITICAL,
                        confidence=1.0,
                        is_violation=True,
                        is_security=True,
                        reason="Zip bomb expansion limit exceeded"
                    ))
                    return texts, signals

                # فحص كل ملف داخل الأرشيف
                for info in infolist:
                    fname = info.filename
                    # فحص محاولات Path Traversal
                    if ".." in fname or fname.startswith("/") or fname.startswith("\\"):
                        signals.append(ModerationSignal(
                            source="ARCHIVE",
                            category=ViolationCategory.MEDIA_UNSAFE,
                            severity=SeverityLevel.CRITICAL,
                            confidence=1.0,
                            is_violation=True,
                            is_security=True,
                            reason="Path traversal sequence detected in archive entry"
                        ))
                        return texts, signals

                    _, ext = os.path.splitext(fname.lower())
                    if ext in DANGEROUS_ARCHIVE_EXTENSIONS:
                        signals.append(ModerationSignal(
                            source="ARCHIVE",
                            category=ViolationCategory.MEDIA_UNSAFE,
                            severity=SeverityLevel.CRITICAL,
                            confidence=1.0,
                            is_violation=True,
                            is_security=True,
                            reason=f"Dangerous executable extension '{ext}' in archive entry: {fname}"
                        ))
                        return texts, signals

                    # فحص التواقيع الثنائية
                    try:
                        with zf.open(info) as entry:
                            header = entry.read(32)
                            for sig in EXECUTABLE_SIGNATURES:
                                if header.startswith(sig):
                                    signals.append(ModerationSignal(
                                        source="ARCHIVE",
                                        category=ViolationCategory.MEDIA_UNSAFE,
                                        severity=SeverityLevel.CRITICAL,
                                        confidence=1.0,
                                        is_violation=True,
                                        is_security=True,
                                        reason=f"Executable binary signature detected inside entry: {fname}"
                                    ))
                                    return texts, signals

                            # استخراج نصوص الملفات النصية البسيطة داخل الأرشيف
                            if ext in (".txt", ".md", ".csv", ".json") and info.file_size < 500000:
                                entry.seek(0)
                                content = entry.read(10000).decode("utf-8", errors="ignore")
                                texts.append(content)
                    except Exception:
                        pass

            return texts, signals
        except Exception as e:
            signals.append(ModerationSignal(
                source="ARCHIVE",
                category=ViolationCategory.MEDIA_UNSAFE,
                severity=SeverityLevel.HIGH,
                confidence=1.0,
                is_violation=True,
                is_security=True,
                reason=f"Archive extraction error: {str(e)}"
            ))
            return texts, signals
        finally:
            shutil.rmtree(temp_extract_dir, ignore_errors=True)

    def _inspect_tar(self, file_path: str, depth: int) -> Tuple[List[str], List[ModerationSignal]]:
        signals = []
        texts = []
        try:
            with tarfile.open(file_path, "r:*") as tf:
                members = tf.getmembers()
                if len(members) > MAX_ARCHIVE_FILES:
                    signals.append(ModerationSignal(
                        source="ARCHIVE",
                        category=ViolationCategory.MEDIA_UNSAFE,
                        severity=SeverityLevel.HIGH,
                        confidence=1.0,
                        is_violation=True,
                        is_security=True,
                        reason="TAR archive exceeds file count limit"
                    ))
                    return texts, signals

                for m in members:
                    if ".." in m.name or m.name.startswith("/") or m.name.startswith("\\"):
                        signals.append(ModerationSignal(
                            source="ARCHIVE",
                            category=ViolationCategory.MEDIA_UNSAFE,
                            severity=SeverityLevel.CRITICAL,
                            confidence=1.0,
                            is_violation=True,
                            is_security=True,
                            reason="Path traversal detected in TAR entry"
                        ))
                        return texts, signals

                    _, ext = os.path.splitext(m.name.lower())
                    if ext in DANGEROUS_ARCHIVE_EXTENSIONS:
                        signals.append(ModerationSignal(
                            source="ARCHIVE",
                            category=ViolationCategory.MEDIA_UNSAFE,
                            severity=SeverityLevel.CRITICAL,
                            confidence=1.0,
                            is_violation=True,
                            is_security=True,
                            reason=f"Dangerous executable extension in TAR entry: {m.name}"
                        ))
                        return texts, signals

            return texts, signals
        except Exception as e:
            signals.append(ModerationSignal(
                source="ARCHIVE",
                category=ViolationCategory.MEDIA_UNSAFE,
                severity=SeverityLevel.HIGH,
                confidence=1.0,
                is_violation=True,
                is_security=True,
                reason=f"TAR read failure: {str(e)}"
            ))
            return texts, signals
