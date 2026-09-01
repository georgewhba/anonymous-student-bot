"""
FSM Submission States.
Single source of truth for all user-facing FSM states.
Both the deep-link entry point (user_start.py) and the reply handler
(user_reply.py) must use the SAME state so aiogram routes correctly.
"""
from aiogram.fsm.state import State, StatesGroup


class SubmissionState(StatesGroup):
    """حالات FSM لعمليات الرد والإرسال المجهول"""
    # الحالة المشتركة: ينتقل إليها الطالب سواء عبر deep link أو زر الرد المباشر
    waiting_for_reply = State()
    waiting_for_dm_reply = State()
