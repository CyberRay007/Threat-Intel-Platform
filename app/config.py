import os
from dotenv import load_dotenv

load_dotenv()

# central configuration
VT_API_KEY = os.getenv("VT_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", CELERY_BROKER_URL)
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
OPENSEARCH_USERNAME = os.getenv("OPENSEARCH_USERNAME", "")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "")
OPENSEARCH_VERIFY_SSL = os.getenv("OPENSEARCH_VERIFY_SSL", "false").lower() == "true"
OPENSEARCH_TIMEOUT = int(os.getenv("OPENSEARCH_TIMEOUT", "5"))
OPENSEARCH_IOC_INDEX = os.getenv("OPENSEARCH_IOC_INDEX", "tip-iocs-v1")
