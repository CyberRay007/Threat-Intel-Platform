import base64
import requests

from app.config import VT_API_KEY


def lookup_domain(domain: str) -> Dict[str, Any]:
    """Query VirusTotal domain endpoint and return parsed results."""
    if not VT_API_KEY:
        return {"malicious": 0, "suspicious": 0, "harmless": 0, "reputation": 0}

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    resp = requests.get(url, headers=headers, timeout=10)
    data = resp.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
        "raw": data,
    }


def lookup_url(url_to_check: str) -> Dict[str, Any]:
    enc = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    if not VT_API_KEY:
        return {}
    url = f"https://www.virustotal.com/api/v3/urls/{enc}"
    headers = {"x-apikey": VT_API_KEY}
    resp = requests.get(url, headers=headers, timeout=10)
    data = resp.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
        "raw": data,
    }


def lookup_file_hash(sha256: str) -> Dict[str, Any]:
    if not VT_API_KEY:
        return {}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}
    resp = requests.get(url, headers=headers, timeout=10)
    data = resp.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {"raw": data, "stats": stats}
