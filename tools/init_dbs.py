import asyncio
import asyncpg
import os

async def main():
    dsn = os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@127.0.0.1:5433/postgres")
    # connect to postgres db first to create anonymous_bot and anonymous_bot_test
    try:
        conn = await asyncpg.connect("postgresql://postgres:postgres@127.0.0.1:5433/postgres")
        for dbname in ["anonymous_bot", "anonymous_bot_test"]:
            exists = await conn.fetchval(f"SELECT 1 FROM pg_database WHERE datname = '{dbname}';")
            if not exists:
                await conn.execute(f"CREATE DATABASE {dbname};")
                print(f"Created database {dbname}")
            else:
                print(f"Database {dbname} exists")
        await conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
