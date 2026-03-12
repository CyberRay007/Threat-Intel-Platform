from typing import Dict, Any
import whois
from datetime import datetime
import math
from collections import Counter
from urllib.parse import urlparse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import IOC, Scan
from app.services import ioc_service, vt_service, risk_engine


def get_domain_age(domain: str) -> int | None:
    """Get domain age in days."""
    try:
        w = whois.whois(domain)
        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        age_days = (datetime.now() - creation).days
        return age_days

    except:
        return None


def check_suspicious_tld(domain: str) -> bool:
    """Check if domain has suspicious TLD."""
    risky_tlds = ["top", "xyz", "tk", "ml", "ga"]
    tld = domain.split(".")[-1].lower()
    return tld in risky_tlds


def calculate_entropy(domain: str) -> float:
    """Calculate Shannon entropy of domain."""
    if not domain:
        return 0.0
    prob = [n_x / len(domain) for x, n_x in Counter(domain).items()]
    entropy = -sum([p_x * math.log2(p_x) for p_x in prob])
    return entropy


def check_phishing_keywords(domain: str) -> bool:
    """Check for phishing keywords in domain."""
    keywords = ["login", "secure", "verify", "update", "account", "bank", "auth", "reset", "apple", "google", "paypal"]
    domain_lower = domain.lower()
    for k in keywords:
        if k in domain_lower:
            return True
    return False


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(url)
    return parsed.netloc.lower()


async def _count_feed_hits(db: AsyncSession, value: str, ioc_type: str) -> int:
    """Return the number of distinct threat feeds that contain this indicator."""
    result = await db.execute(
        select(func.count(func.distinct(IOC.source)))
        .where(IOC.value == value, IOC.type == ioc_type, IOC.source.isnot(None))
    )
    return int(result.scalar() or 0)


async def _historical_domain_behavior(db: AsyncSession, domain: str) -> Dict[str, int]:
    """Return historical behavior signals for previous scans of the same domain."""
    count_result = await db.execute(
        select(func.count(Scan.id)).where(Scan.target_url.ilike(f"%{domain}%"), Scan.status == "completed")
    )
    avg_result = await db.execute(
        select(func.avg(Scan.risk_score)).where(Scan.target_url.ilike(f"%{domain}%"), Scan.status == "completed")
    )
    repeats = int(count_result.scalar() or 0)
    avg_risk = int(float(avg_result.scalar() or 0))
    return {
        # Exclude current in-flight scan by subtracting baseline first encounter.
        "historical_repeat_hits": max(0, repeats - 1),
        "historical_avg_risk": avg_risk,
    }


async def analyze(target_url: str, db: AsyncSession) -> Dict[str, Any]:
    """Perform full domain analysis and return structured result.

    Steps:
    1. Normalize URL and extract domain.
    2. Generate structural signals.
    3. Query IOC service for matches.
    4. Query VT service for reputation counts.
    5. Send signals to risk engine to compute scores.
    6. Return dictionary containing scores, signals and raw data.
    """
    # normalization
    normalized = target_url.strip().lower()
    # extract domain
    domain = extract_domain(normalized)

    # structural signals
    domain_age = get_domain_age(domain)
    young_domain = domain_age is not None and domain_age < 30
    suspicious_tld = check_suspicious_tld(domain)
    entropy = calculate_entropy(domain)
    high_entropy = entropy > 3.5
    phishing_keyword = check_phishing_keywords(domain)

    structural_signals = {
        "domain_length": len(domain),
        "domain_age_days": domain_age,
        "young_domain": young_domain,
        "suspicious_tld": suspicious_tld,
        "entropy": entropy,
        "high_entropy": high_entropy,
        "phishing_keyword": phishing_keyword,
    }

    ioc_result = await ioc_service.check_domain(db, domain)
    vt_result = vt_service.lookup_domain(domain)

    # intelligence feed hit count (distinct sources that ingested this indicator)
    feed_hits = await _count_feed_hits(db, domain, "domain")

    historical = await _historical_domain_behavior(db, domain)

    # build list of signals for risk engine
    signals = []
    # structural
    for name, val in structural_signals.items():
        signals.append({"name": name, "weight": 1, "value": val})
    # vt
    signals.append({"name": "vt_malicious", "weight": 1, "value": vt_result.get("malicious", 0)})
    # ioc correlation
    if ioc_result.get("matched_ioc"):
        signals.append({"name": "ioc_match", "weight": 1, "value": True})
    # intelligence feeds (4th signal — Week 6)
    signals.append({"name": "feed_intel_hits", "weight": 1, "value": feed_hits})
    # historical behavior
    signals.append({"name": "historical_repeat_hits", "weight": 1, "value": historical["historical_repeat_hits"]})
    signals.append({"name": "historical_avg_risk", "weight": 1, "value": historical["historical_avg_risk"]})

    score = risk_engine.score(signals)

    return {
        "domain": domain,
        "signals": structural_signals,
        "ioc": ioc_result,
        "vt": vt_result,
        "score": score,
    }
