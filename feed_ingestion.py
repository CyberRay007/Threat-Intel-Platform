import asyncio
import os
from dotenv import load_dotenv

from app.database.session import AsyncSessionLocal
from app.services.feed_ingestion import ingest_all_sources


load_dotenv()


async def main():
    otx_api_key = os.getenv("OTX_API_KEY")
    async with AsyncSessionLocal() as db:
        result = await ingest_all_sources(db, otx_api_key=otx_api_key)
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
