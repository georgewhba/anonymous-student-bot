"""
Multi-Format Document Analyzer.
Securely extracts text and metadata from TXT, PDF, DOCX, XLSX, and PPTX files.
Detects and rejects macros, embedded binaries, and enforces bounded extraction limits.
"""
import os
import io
import zipfile
from typing import Optional, Tuple, List
from xml.etree import ElementTree as ET
from utils.logger import logger
from moderation.models import (
    ViolationCategory,
    SeverityLevel,
    ModerationSignal
)
from moderation.analyzers.ocr_analyzer import OCRAnalyzer

MAX_DOC_TEXT_CHARS = 50000
MAX_PDF_PAGES = 20
MAX_PDF_OCR_PAGES = 5


class DocumentAnalyzer:
    """محلل المستندات التعليمية بمختلف الصيغ (Document Security & Text Extraction Engine)"""

    def __init__(
        self,
        ocr_analyzer: Optional[OCRAnalyzer] = None,
        fail_closed: bool = True
    ):
        self.ocr_analyzer = ocr_analyzer or OCRAnalyzer(fail_closed=fail_closed)
        self.fail_closed = fail_closed

    def extract_document_text(
        self,
        file_path: str,
        original_filename: Optional[str] = None
    ) -> Tuple[str, List[ModerationSignal]]:
        """
        استخراج النصوص وفحص أمان المستند
        يرجع: (extracted_text, security_signals)
        """
        signals: List[ModerationSignal] = []
        if not os.path.exists(file_path):
            signals.append(ModerationSignal(
                source="DOCUMENT",
                category=ViolationCategory.MEDIA_UNSAFE,
                severity=SeverityLevel.HIGH,
                confidence=1.0,
                is_violation=True,
                is_security=True,
                reason="Document file does not exist on disk"
            ))
            return "", signals

        ext = os.path.splitext(file_path)[1].lower()
        if original_filename:
            ext = os.path.splitext(original_filename)[1].lower() or ext

        try:
            if ext in (".txt", ".csv", ".json", ".md", ".log"):
                text, sig = self._extract_txt(file_path)
                if sig:
                    signals.append(sig)
                return text, signals

            elif ext == ".docx":
                text, docx_sigs = self._extract_docx(file_path)
                signals.extend(docx_sigs)
                return text, signals

            elif ext in (".xlsx", ".xlsm"):
                text, xlsx_sigs = self._extract_xlsx(file_path, ext)
                signals.extend(xlsx_sigs)
                return text, signals

            elif ext in (".pptx", ".pptm"):
                text, pptx_sigs = self._extract_pptx(file_path, ext)
                signals.extend(pptx_sigs)
                return text, signals

            elif ext == ".pdf":
                text, pdf_sigs = self._extract_pdf(file_path)
                signals.extend(pdf_sigs)
                return text, signals

            else:
                signals.append(ModerationSignal(
                    source="DOCUMENT",
                    category=ViolationCategory.MEDIA_UNSAFE,
                    severity=SeverityLevel.HIGH,
                    confidence=1.0,
                    is_violation=True,
                    is_security=True,
                    reason=f"Unsupported document format: '{ext}'"
                ))
                return "", signals

        except Exception as e:
            logger.error(f"خطأ أثناء استخراج نصوص المستند {file_path}: {e}")
            if self.fail_closed:
                signals.append(ModerationSignal(
                    source="DOCUMENT",
                    category=ViolationCategory.MEDIA_UNSAFE,
                    severity=SeverityLevel.HIGH,
                    confidence=1.0,
                    is_violation=True,
                    is_security=True,
                    reason=f"Document parser error: {str(e)}"
                ))
            return "", signals

    def _extract_txt(self, file_path: str) -> Tuple[str, Optional[ModerationSignal]]:
        """استخراج النصوص من ملفات النص العادي مع التحقق من عدم وجود بايتات ثنائية خبيثة"""
        try:
            with open(file_path, "rb") as f:
                header = f.read(256)
                if b"\x00" in header:
                    return "", ModerationSignal(
                        source="DOCUMENT",
                        category=ViolationCategory.MEDIA_UNSAFE,
                        severity=SeverityLevel.CRITICAL,
                        confidence=1.0,
                        is_violation=True,
                        is_security=True,
                        reason="Binary null bytes detected inside plain text file"
                    )

            for enc in ("utf-8", "utf-8-sig", "cp1256", "latin-1"):
                try:
                    with open(file_path, "r", encoding=enc, errors="strict") as f:
                        return f.read(MAX_DOC_TEXT_CHARS), None
                except Exception:
                    continue

            # Fallback with ignore if strict fails
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(MAX_DOC_TEXT_CHARS), None
        except Exception as e:
            return "", ModerationSignal(
                source="DOCUMENT",
                category=ViolationCategory.MEDIA_UNSAFE,
                severity=SeverityLevel.MEDIUM,
                confidence=1.0,
                is_violation=True,
                is_security=True,
                reason=f"TXT read failure: {str(e)}"
            )

    def _extract_docx(self, file_path: str) -> Tuple[str, List[ModerationSignal]]:
        """استخراج نصوص وجداول Word DOCX بأمان مع فحص عدم وجود ماكرو"""
        signals = []
        collected_texts = []
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                # التحقق من عدم وجود ماكرو تنفيذي
                namelist = zf.namelist()
                for name in namelist:
                    if "vbaProject.bin" in name or name.endswith(".bin"):
                        signals.append(ModerationSignal(
                            source="DOCUMENT",
                            category=ViolationCategory.MEDIA_UNSAFE,
                            severity=SeverityLevel.CRITICAL,
                            confidence=1.0,
                            is_violation=True,
                            is_security=True,
                            reason="Macro-enabled VBA binary detected inside DOCX file"
                        ))
                        return "", signals

                # استخراج النصوص من word/document.xml والترويسات
                for xml_name in ("word/document.xml", "word/header1.xml", "word/footer1.xml"):
                    if xml_name in namelist:
                        xml_content = zf.read(xml_name)
                        tree = ET.fromstring(xml_content)
                        for elem in tree.iter():
                            if elem.text:
                                collected_texts.append(elem.text)

            return " ".join(collected_texts)[:MAX_DOC_TEXT_CHARS], signals
        except Exception as e:
            signals.append(ModerationSignal(
                source="DOCUMENT",
                category=ViolationCategory.MEDIA_UNSAFE,
                severity=SeverityLevel.HIGH,
                confidence=1.0,
                is_violation=True,
                is_security=True,
                reason=f"DOCX parser error: {str(e)}"
            ))
            return "", signals

    def _extract_xlsx(self, file_path: str, ext: str) -> Tuple[str, List[ModerationSignal]]:
        """استخراج نصوص وخلايا Excel XLSX ورفض الماكرو .xlsm"""
        signals = []
        if ext == ".xlsm":
            signals.append(ModerationSignal(
                source="DOCUMENT",
                category=ViolationCategory.MEDIA_UNSAFE,
                severity=SeverityLevel.CRITICAL,
                confidence=1.0,
                is_violation=True,
                is_security=True,
                reason="Macro-enabled spreadsheet (.xlsm) is strictly prohibited"
            ))
            return "", signals

        collected = []
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                namelist = zf.namelist()
                for name in namelist:
                    if "vbaProject.bin" in name:
                        signals.append(ModerationSignal(
                            source="DOCUMENT",
                            category=ViolationCategory.MEDIA_UNSAFE,
                            severity=SeverityLevel.CRITICAL,
                            confidence=1.0,
                            is_violation=True,
                            is_security=True,
                            reason="Embedded macro VBA code detected in Excel file"
                        ))
                        return "", signals
                    if "sharedStrings.xml" in name or ("sheet" in name and name.endswith(".xml")):
                        xml_content = zf.read(name)
                        tree = ET.fromstring(xml_content)
                        for elem in tree.iter():
                            if elem.text:
                                collected.append(elem.text)

            return " ".join(collected)[:MAX_DOC_TEXT_CHARS], signals
        except Exception as e:
            signals.append(ModerationSignal(
                source="DOCUMENT",
                category=ViolationCategory.MEDIA_UNSAFE,
                severity=SeverityLevel.HIGH,
                confidence=1.0,
                is_violation=True,
                is_security=True,
                reason=f"XLSX parser error: {str(e)}"
            ))
            return "", signals

    def _extract_pptx(self, file_path: str, ext: str) -> Tuple[str, List[ModerationSignal]]:
        """استخراج نصوص شرائح PowerPoint PPTX ورفض الماكرو والكائنات التنفيذية"""
        signals = []
        if ext == ".pptm":
            signals.append(ModerationSignal(
                source="DOCUMENT",
                category=ViolationCategory.MEDIA_UNSAFE,
                severity=SeverityLevel.CRITICAL,
                confidence=1.0,
                is_violation=True,
                is_security=True,
                reason="Macro-enabled presentation (.pptm) is strictly prohibited"
            ))
            return "", signals

        collected = []
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                namelist = zf.namelist()
                for name in namelist:
                    if "vbaProject.bin" in name or name.endswith((".exe", ".bin", ".dll")):
                        signals.append(ModerationSignal(
                            source="DOCUMENT",
                            category=ViolationCategory.MEDIA_UNSAFE,
                            severity=SeverityLevel.CRITICAL,
                            confidence=1.0,
                            is_violation=True,
                            is_security=True,
                            reason="Dangerous binary / macro found inside PPTX presentation"
                        ))
                        return "", signals
                    if ("slide" in name or "notesSlide" in name) and name.endswith(".xml"):
                        xml_content = zf.read(name)
                        tree = ET.fromstring(xml_content)
                        for elem in tree.iter():
                            if elem.text:
                                collected.append(elem.text)

            return " ".join(collected)[:MAX_DOC_TEXT_CHARS], signals
        except Exception as e:
            signals.append(ModerationSignal(
                source="DOCUMENT",
                category=ViolationCategory.MEDIA_UNSAFE,
                severity=SeverityLevel.HIGH,
                confidence=1.0,
                is_violation=True,
                is_security=True,
                reason=f"PPTX parser error: {str(e)}"
            ))
            return "", signals

    def _extract_pdf(self, file_path: str) -> Tuple[str, List[ModerationSignal]]:
        """استخراج نصوص PDF مع فحص المستندات الممسوحة ضوئياً وتطبيق OCR المقيد"""
        signals: List[ModerationSignal] = []
        extracted_pages = []

        # 1. محاولة الاستخراج عبر PyMuPDF (fitz)
        try:
            import fitz
            doc = fitz.open(file_path)
            num_pages = min(len(doc), MAX_PDF_PAGES)
            for i in range(num_pages):
                page = doc[i]
                page_text = page.get_text() or ""
                extracted_pages.append(page_text)

            # إذا كانت النصوص المستخرجة قليلة جداً والمستند ممسوح ضوئياً (Scanned PDF)
            total_text = " ".join(extracted_pages).strip()
            if len(total_text) < 10 and self.ocr_analyzer.enable_ocr:
                ocr_limit = min(len(doc), MAX_PDF_OCR_PAGES)
                ocr_texts = []
                for i in range(ocr_limit):
                    pix = doc[i].get_pixmap(dpi=150)
                    img_bytes = pix.tobytes("png")
                    ocr_t, ocr_sig = self.ocr_analyzer.extract_text_from_image(io.BytesIO(img_bytes))
                    if ocr_sig:
                        signals.append(ocr_sig)
                    if ocr_t:
                        ocr_texts.append(ocr_t)
                doc.close()
                return " ".join(ocr_texts)[:MAX_DOC_TEXT_CHARS], signals

            doc.close()
            return total_text[:MAX_DOC_TEXT_CHARS], signals
        except Exception:
            pass

        # 2. محاولة احتياطية عبر pypdf
        try:
            import pypdf
            reader = pypdf.PdfReader(file_path)
            num_pages = min(len(reader.pages), MAX_PDF_PAGES)
            for i in range(num_pages):
                page_text = reader.pages[i].extract_text() or ""
                extracted_pages.append(page_text)
            return " ".join(extracted_pages)[:MAX_DOC_TEXT_CHARS], signals
        except Exception as e:
            if self.fail_closed:
                signals.append(ModerationSignal(
                    source="DOCUMENT",
                    category=ViolationCategory.MEDIA_UNSAFE,
                    severity=SeverityLevel.HIGH,
                    confidence=1.0,
                    is_violation=True,
                    is_security=True,
                    reason=f"PDF parser failure: {str(e)}"
                ))

        return "", signals
