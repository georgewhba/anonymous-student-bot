"""
Main Application Entry Point for Anonymous Student Telegram Bot.
Performs startup validation, database initialization, fail-fast channel security checks,
middleware registration, and polling lifecycle management.
"""
import asyncio
import os
import sys

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.types import BotCommand, BotCommandScopeDefault
from aiogram.enums import ChatMemberStatus, ChatType
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from aiohttp import web

from config import get_settings, Settings
from security.crypto import CryptoManager
from security.auth import admin_session_manager
from security.media_sanitizer import media_sanitizer
from database.db_manager import DatabaseManager
from middlewares.throttling import ThrottlingMiddleware
from middlewares.moderation import ModerationCheckMiddleware
from handlers import (
    start_router,
    submit_router,
    reply_router,
    admin_panel_router,
    admin_mod_router,
    admin_msg_router,
    dm_reply_router
)
from utils.logger import logger


from moderation.engine import ModerationEngine
from moderation.publisher import PublisherService


def perform_startup_health_checks(settings: Settings) -> None:
    """التحقق من صحة المكتبات والتبعيات الأساسية عند بدء التشغيل"""
    logger.info("🧪 فحص سلامة التبعيات ومكتبات المعالجة...")
    # 1. فحص مكتبات معالجة PDF
    try:
        import fitz  # PyMuPDF
        logger.info(f"✅ PyMuPDF (fitz) متوفر بنجاح: v{fitz.__version__}")
    except ImportError:
        try:
            import pypdf
            logger.info("✅ pypdf متوفر كبديل لمعالجة PDF")
        except ImportError:
            logger.warning("⚠️ لم يتم العثور على pymupdf أو pypdf. قد يتعذر استخراج نصوص PDF.")

    # 2. فحص محرك OCR إذا كان مفعلاً
    if settings.enable_ocr:
        try:
            import pytesseract
            try:
                tess_ver = pytesseract.get_tesseract_version()
                logger.info(f"✅ Tesseract OCR متوفر على مستوى النظام: v{tess_ver}")
            except Exception as tess_err:
                logger.warning(
                    f"⚠️ مكتبة pytesseract مثبتة، لكن تعذر استدعاء أمر tesseract من النظام ({tess_err}). "
                    "يرجى التأكد من تثبيت tesseract-ocr على نظام التشغيل وضبط PATH."
                )
        except ImportError:
            if settings.fail_closed_on_media_error:
                logger.error("❌ ENABLE_OCR مفعّل و FAIL_CLOSED مفعّل، لكن مكتبة pytesseract غير مثبتة!")
            else:
                logger.warning("⚠️ ENABLE_OCR مفعّل ولكن مكتبة pytesseract غير متوفرة في البيئة.")


async def setup_bot_commands(bot: Bot) -> None:
    """إعداد قائمة الأوامر المعروضة للطلاب في قائمة البوت"""
    commands = [
        BotCommand(command="start", description="بدء المحادثة وعرض المعلومات"),
        BotCommand(command="my_id", description="عرض رقمك المجهول وإحصائياتك"),
        BotCommand(command="rules", description="ضوابط وقوانين النشر في القناة"),
        BotCommand(command="help", description="دليل وطريقة استخدام البوت"),
        BotCommand(command="forget_me", description="طلب حذف بياناتك الشخصية (GDPR)"),
    ]
    try:
        await bot.set_my_commands(commands, scope=BotCommandScopeDefault())
    except Exception as e:
        logger.warning(f"تعذر ضبط أوامر البوت تلقائياً: {e}")


async def validate_channel_configuration(bot: Bot, settings: Settings) -> None:
    """
    التحقق الصارم من القناة الخاصة عند بدء التشغيل (Fail-Fast Validation):
    - وجود القناة
    - نوع القناة (خاصة)
    - وجود البوت كمشرف وصلاحيات النشر والحذف
    - التحقق من عدم وجود مجموعة مناقشة مرتبطة تكسر المجهولية
    """
    logger.info("🔍 بدء فحص أمان وسلامة القناة الخاصة المستهدفة...")
    try:
        chat = await bot.get_chat(chat_id=settings.channel_id)
    except Exception as e:
        logger.error(
            f"❌ خطأ فادح: تعذر الوصول إلى القناة المستهدفة (CHANNEL_ID={settings.channel_id})! "
            f"تأكد من صحة المعرف في .env وإضافة البوت فيها: {e}"
        )
        sys.exit(1)

    # فحص نوع الشات
    if chat.type not in (ChatType.CHANNEL, ChatType.SUPERGROUP):
        logger.warning(f"⚠️ تنبيه: نوع المحادثة المستهدفة هو ({chat.type}). يفضل استخدام Private Channel.")

    # فحص صلاحيات البوت داخل القناة
    try:
        bot_user = await bot.get_me()
        bot_member = await bot.get_chat_member(chat_id=settings.channel_id, user_id=bot_user.id)
        if bot_member.status not in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.CREATOR):
            logger.error("❌ خطأ فادح: البوت ليس مشرفاً (Administrator) داخل القناة الخاصة! يرجى ترقيته ومنحه الصلاحيات.")
            sys.exit(1)

        # فحص صلاحيات الحذف والنشر إن وجدت في الكائن
        if hasattr(bot_member, "can_post_messages") and bot_member.can_post_messages is False:
            logger.error("❌ خطأ فادح: البوت لا يمتلك صلاحية نشر الرسائل (can_post_messages) في القناة!")
            sys.exit(1)

        if hasattr(bot_member, "can_delete_messages") and bot_member.can_delete_messages is False:
            logger.warning("⚠️ تنبيه: البوت لا يمتلك صلاحية حذف الرسائل (can_delete_messages) في القناة.")

    except Exception as e:
        logger.error(f"❌ تعذر التحقق من رتبة وصلاحيات البوت في القناة: {e}")
        sys.exit(1)

    # فحص وجود مجموعة نقاشات مرتبطة
    if getattr(chat, "linked_chat_id", None):
        logger.warning(
            f"⚠️ تنبيه أمني: القناة مرتبطة بمجموعة نقاشات عامة (Linked Chat ID: {chat.linked_chat_id}). "
            "كتابة الطلاب في التعليقات العامة هناك قد تكشف هوياتهم. يُوصى بفصل مجموعة النقاشات."
        )

    logger.info(f"✅ تم التحقق من القناة بنجاح: {chat.title or 'Private Channel'} (ID: {settings.channel_id})")


async def main() -> None:
    """نقطة تشغيل البوت الرئيسية"""
    logger.info("🚀 جاري بدء تشغيل Anonymous Student Telegram Bot...")

    # التحقق من وجود ملف .env أو المتغيرات
    if not os.path.exists(".env") and not os.environ.get("BOT_TOKEN"):
        logger.error("لم يتم العثور على ملف .env! يرجى نسخه من .env.example وتعبئة المتغيرات.")
        sys.exit(1)

    try:
        settings: Settings = get_settings()
    except Exception as e:
        logger.error(f"خطأ في قراءة وتحقق متغيرات البيئة: {e}")
        sys.exit(1)

    # فحص سلامة التبعيات والمكتبات
    perform_startup_health_checks(settings)

    # تنظيف المجلد المؤقت للوسائط
    media_sanitizer.cleanup_all_temp_files()

    # تهيئة التشفير وقاعدة البيانات
    logger.info("🔐 تهيئة نظام التشفير وقاعدة بيانات PostgreSQL المشفرة...")
    try:
        crypto = CryptoManager(settings.encryption_key)
        db = DatabaseManager(
            db_url=settings.database_url,
            crypto=crypto,
            pool_min=settings.database_pool_min,
            pool_max=settings.database_pool_max,
            command_timeout=settings.database_command_timeout,
            connect_timeout=settings.database_connect_timeout,
            ssl_mode=settings.database_ssl_mode
        )
        await db.init_db()
    except Exception as e:
        logger.error(f"فشل تهيئة التشفير أو قاعدة البيانات: {e}")
        sys.exit(1)

    # تهيئة محرك الرقابة وبوابة النشر بالإعدادات النشطة
    moderation_engine = ModerationEngine(settings=settings)
    publisher_service = PublisherService(engine=moderation_engine)

    # تحديث النسخ العامة (Singletons) لتعكس التكوين النشط
    import moderation.engine
    import moderation.publisher
    import utils.content_moderator
    moderation.engine.moderation_engine = moderation_engine
    moderation.publisher.publisher_service = publisher_service
    utils.content_moderator.moderator.engine = moderation_engine

    # تهيئة البوت والموزع (Dispatcher)
    bot = Bot(
        token=settings.bot_token,
        default=DefaultBotProperties(parse_mode="HTML")
    )
    dp = Dispatcher()

    # حقن التبعيات في السياق العام
    dp["settings"] = settings
    dp["db"] = db
    dp["crypto"] = crypto
    dp["moderation_engine"] = moderation_engine
    dp["publisher_service"] = publisher_service

    # تسجيل الوسائط البرمجية (Middlewares)
    dp.message.middleware(ThrottlingMiddleware())
    dp.message.middleware(ModerationCheckMiddleware())

    dp.include_router(admin_panel_router)
    dp.include_router(admin_mod_router)
    dp.include_router(admin_msg_router)
    dp.include_router(dm_reply_router)
    dp.include_router(start_router)
    dp.include_router(reply_router)
    dp.include_router(submit_router)  # يوضع في النهاية لمعالجة باقي الرسائل العامة

    # ضبط أوامر القائمة
    await setup_bot_commands(bot)

    # جلب معلومات البوت والتحقق من الاتصال
    try:
        bot_user = await bot.get_me()
        logger.info(f"✅ تم الاتصال بخوادم تيليجرام: @{bot_user.username} (ID: {bot_user.id})")
        logger.info(f"👑 المسؤول الأساسي (Primary Admin): {settings.primary_admin_id}")
        logger.info(f"🛡️ عدد المشرفين (Moderators): {len(settings.moderator_ids)}")
        if not settings.admin_log_channel_id:
            logger.warning("⚠️ لم يتم تعيين ADMIN_LOG_CHANNEL_ID! لن يتم إرسال سجلات الرقابة إلى أي قناة.")
    except Exception as e:
        logger.error(f"فشل الاتصال بخوادم تيليجرام: {e}")
        sys.exit(1)

    # فحص القناة الصارم
    await validate_channel_configuration(bot, settings)

    # بدء استقبال التحديثات
    try:
        if settings.webhook_url:
            # وضع الإنتاج: Webhook
            await bot.set_webhook(
                url=settings.webhook_url,
                drop_pending_updates=True,
                allowed_updates=dp.resolve_used_update_types()
            )
            logger.info(f"🟢 البوت يعمل الآن في وضع Webhook على: {settings.webhook_url}")
            
            app = web.Application()
            
            # Healthcheck Endpoint
            async def health_check(request: web.Request) -> web.Response:
                try:
                    latency = await db.pool.ping()
                    stats = db.pool.get_pool_stats()
                    return web.json_response({
                        "status": "ok",
                        "database": "connected",
                        "latency_ms": round(latency, 2),
                        "pool": stats
                    })
                except Exception as exc:
                    return web.json_response({"status": "error", "database": str(exc)}, status=503)
                
            app.router.add_get("/health", health_check)
            
            # Webhook Handler
            webhook_requests_handler = SimpleRequestHandler(
                dispatcher=dp,
                bot=bot,
            )
            webhook_requests_handler.register(app, path="/webhook")
            setup_application(app, dp, bot=bot)
            
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, host=settings.webapp_host, port=settings.webapp_port)
            await site.start()
            logger.info(f"🌐 خادم الويب يعمل على {settings.webapp_host}:{settings.webapp_port}")
            
            # إبقاء الـ event loop قيد التشغيل
            await asyncio.Event().wait()
            
        else:
            # وضع التطوير: Polling
            await bot.delete_webhook(drop_pending_updates=True)
            logger.info("🟢 البوت جاهز ويستقبل الآن الرسائل (وضع Polling).")
            await dp.start_polling(bot)
            
    finally:
        media_sanitizer.cleanup_all_temp_files()
        await db.close()
        await bot.session.close()
        logger.info("تم إيقاف تشغيل البوت بأمان.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("تم إنهاء تشغيل البرنامج.")
