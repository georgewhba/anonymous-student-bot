from handlers.user_start import router as start_router
from handlers.user_submit import router as submit_router
from handlers.user_reply import router as reply_router
from handlers.admin_panel import router as admin_panel_router
from handlers.admin_moderation import router as admin_mod_router
from handlers.admin_messaging import router as admin_msg_router
from handlers.student_dm_reply import router as dm_reply_router

__all__ = [
    "start_router",
    "submit_router",
    "reply_router",
    "admin_panel_router",
    "admin_mod_router",
    "admin_msg_router",
    "dm_reply_router",
]
