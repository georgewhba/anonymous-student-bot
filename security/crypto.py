"""
Cryptographic operations module.
Uses Fernet (authenticated symmetric encryption: AES-128-CBC with HMAC-SHA256 authentication)
and HMAC-SHA256 for deterministic blind indexing of user identifiers.
"""
import hashlib
import hmac
from typing import Optional, Union
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class CryptoManager:
    """
    نظام تشفير وحماية بيانات الهوية والخصوصية للطلاب.
    يستخدم Fernet (تشفير متماثل موثق: AES-128-CBC مع توقيع HMAC-SHA256).
    ويستخدم مفتاح HMAC-SHA256 منفصلاً مشتقاً عبر HKDF لعمل هاش أعمى للمعرفات.
    """

    def __init__(self, key: Union[str, bytes]):
        if isinstance(key, str):
            key = key.strip().encode("utf-8")
        try:
            self._fernet = Fernet(key)
        except Exception as e:
            raise ValueError(f"مفتاح التشفير ENCRYPTION_KEY غير صالح. يجب أن يكون 32-byte urlsafe base64: {e}")
        self._key_bytes = key
        self._hmac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"anonymous-student-bot-hmac-index",
        ).derive(self._key_bytes)

    @property
    def key(self) -> str:
        return self._key_bytes.decode("utf-8")

    def encrypt(self, data: Optional[Union[str, int]]) -> Optional[str]:
        """تشفير نص أو رقم وإرجاع نص مشفر Base64"""
        if data is None:
            return None
        data_str = str(data)
        encrypted_bytes = self._fernet.encrypt(data_str.encode("utf-8"))
        return encrypted_bytes.decode("utf-8")

    def decrypt(self, encrypted_data: Optional[str]) -> Optional[str]:
        """فك تشفير النص المشفر"""
        if not encrypted_data:
            return None
        if str(encrypted_data).startswith("[WIPED]"):
            return "[WIPED]"
        try:
            decrypted_bytes = self._fernet.decrypt(encrypted_data.encode("utf-8"))
            return decrypted_bytes.decode("utf-8")
        except InvalidToken:
            return "[خطأ في فك التشفير أو مفتاح غير صالح]"
        except Exception:
            return "[بيانات تالفة]"

    def decrypt_int(self, encrypted_data: Optional[str]) -> Optional[int]:
        """فك تشفير نص مشفر وتحويله إلى رقم صحيح (مثل Telegram ID)"""
        val = self.decrypt(encrypted_data)
        if val and (val.isdigit() or (val.startswith("-") and val[1:].isdigit())):
            return int(val)
        return None

    def create_user_hash(self, telegram_id: int) -> str:
        """
        إنشاء هاش أعمى أحادي الاتجاه للمعرف للبحث السريع في قاعدة البيانات
        دون الحاجة لتخزين الآيدي مكشوفاً باستخدام مفتاح HMAC منفصل مشتق عبر HKDF.
        """
        h = hmac.new(
            self._hmac_key,
            msg=str(telegram_id).encode("utf-8"),
            digestmod=hashlib.sha256
        )
        return h.hexdigest()
