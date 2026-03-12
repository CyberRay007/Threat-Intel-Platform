import hashlib
import magic
from typing import Dict, Any, Tuple

from app.services import vt_service


def generate_file_hash(file_content: bytes) -> Tuple[str, str]:
    """Generate SHA256 and MD5 hashes for file."""
    sha256 = hashlib.sha256(file_content).hexdigest()
    md5 = hashlib.md5(file_content).hexdigest()
    return sha256, md5


def get_file_type(file_content: bytes) -> str:
    """Get file type using magic."""
    try:
        return magic.from_buffer(file_content)
    except:
        return "unknown"


async def analyze_file(file_content: bytes, filename: str) -> Dict[str, Any]:
    """Analyze file for threats."""
    sha256, md5 = generate_file_hash(file_content)
    file_type = get_file_type(file_content)

    # Check VirusTotal
    vt_result = vt_service.lookup_file_hash(sha256)
    if not vt_result.get("stats"):
        # File not known, upload it
        upload_result = vt_service.upload_file(file_content, filename)
        # For simplicity, assume upload succeeds and return basic info
        vt_result = {"uploaded": True, "raw": upload_result.get("raw")}

    # Basic risk scoring based on VT
    malicious = vt_result.get("stats", {}).get("malicious", 0)
    risk_score = min(malicious * 10, 100)  # Simple scoring

    return {
        "filename": filename,
        "sha256": sha256,
        "md5": md5,
        "file_type": file_type,
        "vt_result": vt_result,
        "risk_score": risk_score,
    }