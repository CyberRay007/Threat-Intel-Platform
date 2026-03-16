import os
from sqlalchemy import create_engine, text


DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://threat_user:password@localhost:5432/threat_intel_db"
)


def try_connect(url: str) -> bool:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            result = connection.execute(text("SELECT 1"))
            print(f"Connection successful ({url.split(':')[0]}):", result.scalar())
        return True
    except Exception as exc:
        print(f"Connection failed for {url!r}: {exc}")
        return False


if __name__ == "__main__":
    # Try configured database first
    if try_connect(DATABASE_URL):
        pass
    else:
        # Fallback to in-memory SQLite for local testing
        print("Falling back to in-memory SQLite for a quick sanity check.")
        sqlite_url = "sqlite+pysqlite:///:memory:"
        if not try_connect(sqlite_url):
            print("All connection attempts failed. Check your DATABASE_URL and database server.")
            raise SystemExit(1)