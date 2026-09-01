import asyncio
import os
from aiogram import Bot, Dispatcher, F
from aiogram.types import Message
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("BOT_TOKEN")
if not TOKEN:
    print("يرجى التأكد من وجود BOT_TOKEN في ملف .env")
    exit(1)

bot = Bot(token=TOKEN)
dp = Dispatcher()


@dp.channel_post()
async def handle_channel_post(message: Message):
    print("=" * 60)
    print(f"🎉 تم استلام رسالة من القناة بنجاح!")
    print(f"📢 اسم القناة: {message.chat.title}")
    print(f"🆔 معرف القناة (CHANNEL_ID): {message.chat.id}")
    print("=" * 60)
    print(f"قم بنسخ هذا المعرف ({message.chat.id}) وضعه في ملف .env كالتالي:")
    print(f"CHANNEL_ID={message.chat.id}")
    print("=" * 60)


@dp.message()
async def handle_user_msg(message: Message):
    if message.forward_from_chat:
        print("=" * 60)
        print(f"🎉 تم اكتشاف القناة من الرسالة المحولة:")
        print(f"📢 اسم القناة: {message.forward_from_chat.title}")
        print(f"🆔 معرف القناة (CHANNEL_ID): {message.forward_from_chat.id}")
        print("=" * 60)
        await message.answer(
            f"✅ <b>معلومات القناة:</b>\n\n"
            f"📢 <b>الاسم:</b> {message.forward_from_chat.title}\n"
            f"🆔 <b>CHANNEL_ID:</b> <code>{message.forward_from_chat.id}</code>\n\n"
            f"قم بوضع هذا المعرف في ملف <code>.env</code>.",
            parse_mode="HTML"
        )
    else:
        await message.answer(
            f"🆔 <b>معرف حسابك الشخصي (Telegram ID):</b> <code>{message.from_user.id}</code>\n\n"
            f"لمعرفة معرف القناة الخاصة:\n"
            f"1. أضف البوت مشرفاً (Admin) في القناة الخاصة.\n"
            f"2. أرسل أي رسالة داخل القناة أو قم بإعادة توجيه أي منشور منها إلى هنا.",
            parse_mode="HTML"
        )


async def main():
    bot_info = await bot.get_me()
    print(f"🔍 أداة جلب معرف القناة جاهزة - البوت: @{bot_info.username}")
    print("1. أضف البوت مشرفاً في القناة الخاصة.")
    print("2. اكتب أي رسالة داخل القناة، وسيظهر معرف القناة فوراً هنا.")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
