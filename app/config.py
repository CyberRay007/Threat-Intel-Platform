import os
from dotenv import load_dotenv

load_dotenv()

# central configuration
VT_API_KEY = os.getenv("VT_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", CELERY_BROKER_URL)
