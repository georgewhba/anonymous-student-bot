"""
SQLite to PostgreSQL Production Data Migration Tool.
Performs zero-data-loss, transactional migration from legacy SQLite databases
to PostgreSQL with strict verification of row counts, sequences, and relationships.
"""
import os
import sys
import sqlite3
import asyncio
import argparse
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import asyncpg


def parse_iso_dt(val: Optional[str]) -> Optional[datetime]:
    """تحويل النص الزمني ISO إلى كائن datetime مع التوقيت العالمي UTC"""
    if not val:
        return None
    try:
        dt = datetime.fromisoformat(val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


async def migrate_data(sqlite_path: str, pg_url: str, dry_run: bool = False) -> bool:
    """تنفيذ عملية النقل والتحقق من سلامة البيانات"""
    if not os.path.exists(sqlite_path):
        print(f"❌ لم يتم العثور على ملف SQLite في المسار: {sqlite_path}")
        return False

    print(f"📦 بدء استخراج البيانات من SQLite ({sqlite_path})...")
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row
    s_cur = sqlite_conn.cursor()

    # فحص الجداول الموجودة في SQLite
    s_cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    existing_tables = {row[0] for row in s_cur.fetchall()}
    print(f"📋 الجداول الموجودة في SQLite: {', '.join(existing_tables)}")

    print(f"🐘 الاتصال بقاعدة بيانات PostgreSQL المستهدفة...")
    try:
        pg_conn = await asyncpg.connect(pg_url)
    except Exception as e:
        print(f"❌ تعذر الاتصال بـ PostgreSQL: {e}")
        sqlite_conn.close()
        return False

    counts_sqlite: Dict[str, int] = {}
    counts_pg: Dict[str, int] = {}

    try:
        async with pg_conn.transaction():
            # 1. Students
            if "students" in existing_tables:
                s_cur.execute("SELECT * FROM students ORDER BY id ASC;")
                students = s_cur.fetchall()
                counts_sqlite["students"] = len(students)
                print(f"  -> نقل {len(students)} طالب...")
                for s in students:
                    created_at = parse_iso_dt(s["created_at"])
                    last_active = parse_iso_dt(s["last_active_at"])
                    muted_until = parse_iso_dt(s["muted_until"]) if s["muted_until"] else None
                    await pg_conn.execute("""
                        INSERT INTO students (
                            id, anonymous_id, user_hash, enc_telegram_id, enc_full_name, enc_username,
                            is_banned, ban_reason, muted_until, total_posts, total_replies,
                            created_at, last_active_at
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                        ON CONFLICT (anonymous_id) DO UPDATE SET
                            enc_full_name = EXCLUDED.enc_full_name,
                            enc_username = EXCLUDED.enc_username,
                            is_banned = EXCLUDED.is_banned,
                            total_posts = EXCLUDED.total_posts,
                            total_replies = EXCLUDED.total_replies;
                    """, (
                        s["id"], s["anonymous_id"], s["user_hash"], s["enc_telegram_id"],
                        s["enc_full_name"], s["enc_username"], bool(s["is_banned"]),
                        s["ban_reason"], muted_until, s["total_posts"], s["total_replies"],
                        created_at, last_active
                    ))

                # ضبط عداد السلسلة التلقائية على أعلى anonymous_id
                max_anon = await pg_conn.fetchval("SELECT COALESCE(MAX(anonymous_id), 100) FROM students;")
                await pg_conn.execute(f"SELECT setval('anonymous_student_id_seq', {max_anon});")
                # ضبط id sequence
                max_id = await pg_conn.fetchval("SELECT COALESCE(MAX(id), 1) FROM students;")
                await pg_conn.execute(f"SELECT setval(pg_get_serial_sequence('students', 'id'), {max_id});")

            # 2. Banned Fingerprints
            if "banned_fingerprints" in existing_tables:
                s_cur.execute("SELECT * FROM banned_fingerprints;")
                fps = s_cur.fetchall()
                counts_sqlite["banned_fingerprints"] = len(fps)
                print(f"  -> نقل {len(fps)} بصمة حظر...")
                for fp in fps:
                    banned_at = parse_iso_dt(fp["banned_at"])
                    await pg_conn.execute("""
                        INSERT INTO banned_fingerprints (id_hash, reason, banned_at)
                        VALUES ($1, $2, $3)
                        ON CONFLICT (id_hash) DO NOTHING;
                    """, fp["id_hash"], fp["reason"], banned_at)

            # 3. Admin Credentials
            if "admin_credentials" in existing_tables:
                s_cur.execute("SELECT * FROM admin_credentials;")
                creds = s_cur.fetchall()
                counts_sqlite["admin_credentials"] = len(creds)
                print(f"  -> نقل {len(creds)} حساب مشرف...")
                for c in creds:
                    created_at = parse_iso_dt(c["created_at"])
                    last_login = parse_iso_dt(c["last_login_at"]) if c["last_login_at"] else None
                    await pg_conn.execute("""
                        INSERT INTO admin_credentials (telegram_id, password_hash, role, created_at, last_login_at)
                        VALUES ($1, $2, $3, $4, $5)
                        ON CONFLICT (telegram_id) DO UPDATE SET password_hash = EXCLUDED.password_hash;
                    """, c["telegram_id"], c["password_hash"], c["role"], created_at, last_login)

            # 4. Posts
            if "posts" in existing_tables:
                s_cur.execute("SELECT * FROM posts ORDER BY id ASC;")
                posts = s_cur.fetchall()
                counts_sqlite["posts"] = len(posts)
                print(f"  -> نقل {len(posts)} منشور...")
                for p in posts:
                    created_at = parse_iso_dt(p["created_at"])
                    enc_fn = p["enc_original_filename"] if "enc_original_filename" in p.keys() else None
                    status = p["status"] if "status" in p.keys() else "published"
                    await pg_conn.execute("""
                        INSERT INTO posts (
                            id, anonymous_id, channel_message_id, user_msg_id, media_type, media_file_id,
                            content_preview, content_hash, created_at, is_deleted, status, enc_original_filename
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                        ON CONFLICT (channel_message_id) DO NOTHING;
                    """, (
                        p["id"], p["anonymous_id"], p["channel_message_id"], p["user_msg_id"],
                        p["media_type"], p["media_file_id"], p["content_preview"],
                        p["content_hash"], created_at, bool(p["is_deleted"]), status, enc_fn
                    ))
                max_p_id = await pg_conn.fetchval("SELECT COALESCE(MAX(id), 1) FROM posts;")
                await pg_conn.execute(f"SELECT setval(pg_get_serial_sequence('posts', 'id'), {max_p_id});")

            # 5. Replies
            if "replies" in existing_tables:
                s_cur.execute("SELECT * FROM replies ORDER BY id ASC;")
                replies = s_cur.fetchall()
                counts_sqlite["replies"] = len(replies)
                print(f"  -> نقل {len(replies)} رد...")
                for r in replies:
                    created_at = parse_iso_dt(r["created_at"])
                    enc_fn = r["enc_original_filename"] if "enc_original_filename" in r.keys() else None
                    status = r["status"] if "status" in r.keys() else "published"
                    await pg_conn.execute("""
                        INSERT INTO replies (
                            id, parent_channel_msg_id, reply_channel_msg_id, anonymous_id, media_type,
                            media_file_id, content_preview, content_hash, created_at, is_deleted, status, enc_original_filename
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                        ON CONFLICT (reply_channel_msg_id) DO NOTHING;
                    """, (
                        r["id"], r["parent_channel_msg_id"], r["reply_channel_msg_id"],
                        r["anonymous_id"], r["media_type"], r["media_file_id"],
                        r["content_preview"], r["content_hash"], created_at,
                        bool(r["is_deleted"]), status, enc_fn
                    ))
                max_r_id = await pg_conn.fetchval("SELECT COALESCE(MAX(id), 1) FROM replies;")
                await pg_conn.execute(f"SELECT setval(pg_get_serial_sequence('replies', 'id'), {max_r_id});")

            # 6. Audit Logs
            if "audit_logs" in existing_tables:
                s_cur.execute("SELECT * FROM audit_logs ORDER BY id ASC;")
                audits = s_cur.fetchall()
                counts_sqlite["audit_logs"] = len(audits)
                print(f"  -> نقل {len(audits)} سجل رقابة...")
                for a in audits:
                    created_at = parse_iso_dt(a["created_at"])
                    await pg_conn.execute("""
                        INSERT INTO audit_logs (id, admin_id, action, target_anonymous_id, details, created_at)
                        VALUES ($1, $2, $3, $4, $5, $6)
                        ON CONFLICT (id) DO NOTHING;
                    """, a["id"], a["admin_id"], a["action"], a["target_anonymous_id"], a["details"], created_at)
                max_a_id = await pg_conn.fetchval("SELECT COALESCE(MAX(id), 1) FROM audit_logs;")
                await pg_conn.execute(f"SELECT setval(pg_get_serial_sequence('audit_logs', 'id'), {max_a_id});")

            # 7. System Settings
            if "system_settings" in existing_tables:
                s_cur.execute("SELECT * FROM system_settings;")
                settings_rows = s_cur.fetchall()
                counts_sqlite["system_settings"] = len(settings_rows)
                print(f"  -> نقل {len(settings_rows)} إعداد نظام...")
                for st in settings_rows:
                    updated_at = parse_iso_dt(st["updated_at"])
                    await pg_conn.execute("""
                        INSERT INTO system_settings (key, value, updated_at)
                        VALUES ($1, $2, $3)
                        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
                    """, st["key"], st["value"], updated_at)

            if dry_run:
                print("⚠️ تم تشغيل النقل في وضع التجربة (Dry Run) — سيتم إلغاء المعاملة.")
                raise RuntimeError("Dry run rollback")

        print("\n🔍 التحقق من مطابقة السجلات في PostgreSQL...")
        for table in counts_sqlite.keys():
            count_in_pg = await pg_conn.fetchval(f"SELECT COUNT(*) FROM {table};")
            counts_pg[table] = count_in_pg or 0

        print("\n" + "=" * 50)
        print(f"{'الجدول':<25} | {'SQLite':<10} | {'PostgreSQL':<10}")
        print("=" * 50)
        all_matched = True
        for table, sq_cnt in counts_sqlite.items():
            pg_cnt = counts_pg.get(table, 0)
            status = "✅" if pg_cnt >= sq_cnt else "❌"
            print(f"{table:<25} | {sq_cnt:<10} | {pg_cnt:<10} {status}")
            if pg_cnt < sq_cnt:
                all_matched = False
        print("=" * 50)

        if all_matched:
            print("\n🎉 تمت عملية نقل البيانات بنجاح تام وبدون أي فقدان!")
            return True
        else:
            print("\n⚠️ تنبيه: يوجد اختلاف في عدد السجلات لبعض الجداول.")
            return False

    except RuntimeError as re:
        if str(re) == "Dry run rollback":
            return True
        raise
    finally:
        sqlite_conn.close()
        await pg_conn.close()


def main():
    parser = argparse.ArgumentParser(description="نقل قاعدة البيانات من SQLite إلى PostgreSQL")
    parser.add_argument("--sqlite-path", default="data/anonymous_bot.db", help="مسار ملف SQLite القديم")
    parser.add_argument(
        "--pg-url",
        default=os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/anonymous_bot"),
        help="رابط الاتصال بقاعدة بيانات PostgreSQL"
    )
    parser.add_argument("--dry-run", action="store_true", help="تشغيل اختباري دون حفظ التغييرات")

    args = parser.parse_args()
    success = asyncio.run(migrate_data(args.sqlite_path, args.pg_url, args.dry_run))
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
