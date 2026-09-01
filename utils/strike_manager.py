"""
Security Shield and Auto-Escalation Manager.
Handles in-memory rapid flood bursts and progressive strike penalties.
"""
import time
from typing import Dict, List, Tuple, Optional
from database.db_manager import DatabaseManager
from utils.logger import logger, send_admin_log_notification
from aiogram import Bot

# تتبع الانتهاكات في الذاكرة: {user_id: [timestamp1, timestamp2, ...]}
_user_violations: Dict[int, List[float]] = {}

# تتبع سرعة الرسائل لمنع الإغراق: {user_id: [timestamp1, timestamp2, ...]}
_message_history: Dict[int, List[float]] = {}


class SecurityShield:
    """
    درع الحماية ومكافحة السبام وتصعيد العقوبات التلقائي (Auto-Escalation Shield)
    يطبق نظام الإنذارات (Strikes) والكتم التلقائي لمن يحاول إغراق البوت أو إرسال محتوى ممنوع.
    """

    @classmethod
    def check_rate_and_flood(cls, user_id: int) -> Tuple[bool, str]:
        """
        فحص سرعة إرسال الرسائل (Sliding Window Flood Detection)
        - منع أكثر من 3 رسائل خلال 6 ثوانٍ (Rapid Fire)
        - منع أكثر من 10 رسائل خلال 60 ثانية (Burst Flooding)
        """
        now = time.time()
        history = _message_history.get(user_id, [])
        history = [t for t in history if now - t < 60]
        history.append(now)
        _message_history[user_id] = history

        # فحص الرشقات السريعة جداً (Rapid Fire)
        recent_3 = [t for t in history if now - t < 6]
        if len(recent_3) > 3:
            return False, "⏱️ <b>يرجى التمهل!</b> أنت ترسل الرسائل بسرعة فائقة. تم إيقاف الرسالة لحماية الخادم."

        # فحص إجمالي الدقيقة
        if len(history) > 10:
            return False, "⚠️ <b>تم حظر إرسال الرسائل مؤقتاً لدقيقة</b> بسبب تجاوز الحد المسموح من الرسائل المتتالية."

        return True, ""

    @classmethod
    async def record_violation(
        cls,
        user_id: int,
        anonymous_id: int,
        violation_name: str,
        db: DatabaseManager,
        bot: Bot,
        admin_log_channel_id: Optional[int]
    ) -> Tuple[int, Optional[str]]:
        """
        تسجيل إنذار وتطبيق العقوبة التلقائية التصاعدية
        يرجع: (عدد_الإنذارات_الحالية, رسالة_العقوبة_إن_وجدت)
        """
        # تسجيل الحدث الأمني في قاعدة البيانات والذاكرة
        try:
            await db.record_security_event(user_id=user_id, event_type="VIOLATION", details=violation_name)
            strike_count = await db.get_recent_security_events_count(user_id=user_id, event_type="VIOLATION", window_seconds=900)
        except Exception as e:
            logger.debug(f"Could not persist security event: {e}")
            now = time.time()
            violations = _user_violations.get(user_id, [])
            violations = [t for t in violations if now - t < 900]
            violations.append(now)
            _user_violations[user_id] = violations
            strike_count = len(violations)

        # تحديث الذاكرة السريعة
        now = time.time()
        violations = _user_violations.get(user_id, [])
        violations = [t for t in violations if now - t < 900]
        violations.append(now)
        _user_violations[user_id] = violations

        if strike_count == 1:
            return 1, None

        elif strike_count == 2:
            return 2, "⚠️ <b>تحذير أمني:</b> تكرار إرسال محتوى مخالف قد يؤدي لكتم حسابك تلقائياً."

        elif strike_count == 3:
            mute_mins = 15
            await db.mute_student(anonymous_id, mute_mins)
            await db.log_audit_action(
                admin_id=0,
                action="AUTO_MUTE",
                target_anonymous_id=anonymous_id,
                details=f"تم كتم الطالب #{anonymous_id} تلقائياً لمدة {mute_mins} دقيقة لتكرار المخالفات ({violation_name})"
            )
            await send_admin_log_notification(
                bot,
                admin_log_channel_id,
                f"🛡️ <b>كتم أمني تلقائي (Auto-Mute)</b>\n"
                f"الهدف: <code>طالب #{anonymous_id}</code>\n"
                f"السبب: تكرار إرسال محتوى مخالف (3 إنذارات متتالية)\n"
                f"المدة: <b>{mute_mins}</b> دقيقة"
            )
            return 3, f"⏳ <b>تم إيقافك عن النشر تلقائياً لمدة {mute_mins} دقيقة</b> لتكرار إرسال محتوى مخالف لأنظمة القناة."

        else:
            mute_mins = 120
            await db.mute_student(anonymous_id, mute_mins)
            await db.log_audit_action(
                admin_id=0,
                action="AUTO_MUTE_EXTENDED",
                target_anonymous_id=anonymous_id,
                details=f"تم كتم الطالب #{anonymous_id} تلقائياً لمدة {mute_mins} دقيقة بسبب الإغراق المتعمد"
            )
            await send_admin_log_notification(
                bot,
                admin_log_channel_id,
                f"🚨 <b>كتم أمني مشدد (High-Priority Alert)</b>\n"
                f"الهدف: <code>طالب #{anonymous_id}</code>\n"
                f"السبب: محاولات متكررة لإغراق البوت أو إرسال محتوى محظور\n"
                f"المدة: <b>ساعتان ({mute_mins} دقيقة)</b>"
            )
            return strike_count, f"🚫 <b>تم كتم حسابك لمدة ساعتين</b> لتجاوز الحدود الأمنية ومحاولة تكرار المخالفات."
