"""
HTML and text escaping module.
Guarantees that all user-supplied content, captions, and filenames
are properly sanitized before inclusion in Telegram HTML messages.
"""
import html
from typing import Optional


def escape_user_content(text: Optional[str]) -> str:
    """
    تعقيم وتأمين أي نص مدخل من المستخدم ضد ثغرات حقن HTML.
    يحول < و > و & و " إلى رموز HTML آمنة.
    """
    if not text:
        return ""
    return html.escape(text.strip(), quote=True)


def build_channel_post_html(anonymous_id: int, text_content: Optional[str]) -> str:
    """بناء الرسالة المنشورة في القناة لسؤال جديد بشكل آمن تماماً"""
    header = (
        f"🎓 <b>سؤال / استفسار جديد</b>\n"
        f"👤 <b>المرسل:</b> <code>طالب #{anonymous_id}</code>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
    )
    if text_content and text_content.strip():
        safe_body = escape_user_content(text_content)
        return f"{header}{safe_body}"
    return header


def build_channel_reply_html(
    anonymous_id: int,
    parent_channel_msg_id: int,
    text_content: Optional[str]
) -> str:
    """بناء الرسالة المنشورة في القناة لرد مجهول بشكل آمن تماماً"""
    header = (
        f"🔄 <b>رد جديد من:</b> <code>طالب #{anonymous_id}</code>\n"
        f"📌 <i>تعقيباً على المنشور #{parent_channel_msg_id}</i>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
    )
    if text_content and text_content.strip():
        safe_body = escape_user_content(text_content)
        return f"{header}{safe_body}"
    return header
