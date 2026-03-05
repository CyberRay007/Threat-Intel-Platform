import asyncio
from sqlalchemy import text
from app.database.session import async_engine

async def main():
    async with async_engine.begin() as conn:
        # add columns if missing
        # alter scan_results table one command at a time
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS structural_score integer DEFAULT 0"))
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS vt_score integer DEFAULT 0"))
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS ioc_score integer DEFAULT 0"))
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS risk_score integer DEFAULT 0"))
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS signals_json jsonb DEFAULT '{}'::jsonb"))
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS vt_raw_json jsonb DEFAULT '{}'::jsonb"))
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS summary text DEFAULT ''"))
        # create file_scans table if not exists
        await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS file_scans (
            id serial ,
            user_id integer NOT NULL references users(id),
            filename varchar NOT NULL,
            sha256 varchar NOT NULL,
            vt_score integer DEFAULT 0,
            risk_score integer DEFAULT 0,
            vt_raw_json jsonb DEFAULT '{}'::jsonb,
            status varchar DEFAULT 'pending',
            created_at timestamp without time zone DEFAULT now(),
            completed_at timestamp without time zone
        )
        """))
        # add indexes separately
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_user_id ON scans(user_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scan_results_scan_id ON scan_results(scan_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_file_scans_sha256 ON file_scans(sha256)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_value ON ioc(value)"))
        print("Schema updates applied.")

if __name__ == '__main__':
    asyncio.run(main())
