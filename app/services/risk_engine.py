from typing import List, Dict, Any

# ---------------------------------------------------------------------------
# Week 6 — Multi-signal threat scoring engine
#
# Each of the four components is scored independently on a 0–100 raw scale,
# then scaled to its 25-point budget.  Final risk score is always 0–100.
#
# Component       Weight   Budget
# ─────────────────────────────────
# structural       25 %     25 pts
# ioc              25 %     25 pts
# vt               25 %     25 pts
# feed_intel       25 %     25 pts
# ─────────────────────────────────
# Total                    100 pts
# ---------------------------------------------------------------------------

_RISK_THRESHOLDS = [
    (76, "critical"),
    (51, "high"),
    (26, "medium"),
    (0,  "low"),
]


def risk_level(total_score: int) -> str:
    """Return a human-readable severity label for a 0–100 score."""
    for threshold, label in _RISK_THRESHOLDS:
        if total_score >= threshold:
            return label
    return "low"


def _score_structural(signals: List[Dict[str, Any]]) -> int:
    """Score structural signals on a 0–100 raw scale, then cap at 25."""
    raw = 0
    for s in signals:
        name = s.get("name")
        v = s.get("value")
        if name == "young_domain" and v:
            raw += 30
        elif name == "suspicious_tld" and v:
            raw += 25
        elif name == "high_entropy" and v:
            raw += 25
        elif name == "phishing_keyword" and v:
            raw += 20
        elif name == "ip_domain" and v:
            raw += 30
        elif name == "domain_length":
            # long subdomain chains are suspicious; saturates at len>=30
            raw += min(int(len(str(v)) / 30 * 20), 20)
    return min(raw, 100) * 25 // 100


def _score_ioc(signals: List[Dict[str, Any]]) -> int:
    """Score IOC correlation signals, capped at 25."""
    raw = 0
    for s in signals:
        name = s.get("name")
        v = s.get("value")
        if name == "ioc_match" and v:
            # strong signal — at least one direct IOC match
            raw += 100
    return min(raw, 100) * 25 // 100


def _score_vt(signals: List[Dict[str, Any]]) -> int:
    """Score VirusTotal detections, capped at 25.

    vt_malicious value is the engine count; ≥10 = saturated.
    """
    raw = 0
    for s in signals:
        if s.get("name") == "vt_malicious":
            count = int(s.get("value") or 0)
            # each detection adds 10 raw points; saturates at 10 engines
            raw += min(count * 10, 100)
    return min(raw, 100) * 25 // 100


def _score_feed_intel(signals: List[Dict[str, Any]]) -> int:
    """Score intelligence-feed hits, capped at 25.

    feed_intel_hits: number of distinct threat feeds that flagged the indicator.
    feed_intel_match: boolean, any feed hit at all.
    """
    raw = 0
    for s in signals:
        name = s.get("name")
        v = s.get("value")
        if name == "feed_intel_hits":
            hits = int(v or 0)
            # 1 feed  → 40 raw, each additional +20, saturates at 4 feeds
            if hits > 0:
                raw += min(40 + (hits - 1) * 20, 100)
        elif name == "feed_intel_match" and v:
            raw = max(raw, 40)
    return min(raw, 100) * 25 // 100


def _score_historical(signals: List[Dict[str, Any]]) -> int:
    """Score historical behavior from repeat malicious activity, capped at 25.

    historical_repeat_hits: count of prior suspicious observations for the same target.
    historical_avg_risk: average previous risk score in 0-100.
    """
    raw = 0
    for s in signals:
        name = s.get("name")
        v = s.get("value")
        if name == "historical_repeat_hits":
            hits = int(v or 0)
            # 1 prior hit starts risk trend; saturates quickly for repeat offenders.
            if hits > 0:
                raw += min(30 + (hits - 1) * 15, 100)
        elif name == "historical_avg_risk":
            avg = max(0, min(int(v or 0), 100))
            raw = max(raw, avg)
    return min(raw, 100) * 25 // 100


def score(signals: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute the multi-signal risk score from a flat signal list.

    Returns a dict with per-component scores and total 0–100 risk.

    Week 6 primary weighting remains 25/25/25/25 across structural, IOC,
    VT, and intelligence-feed components. Historical behavior is blended
    into the intelligence-feed component so the final model considers
    historical context while retaining a stable 0–100 scale.
    """
    structural = _score_structural(signals)
    ioc        = _score_ioc(signals)
    vt         = _score_vt(signals)
    feed       = _score_feed_intel(signals)
    historical = _score_historical(signals)
    feed_intel = int(round((feed * 0.6) + (historical * 0.4)))
    total      = structural + ioc + vt + feed_intel

    return {
        "structural_score": structural,
        "ioc_score":        ioc,
        "vt_score":         vt,
        "feed_intel_score": feed_intel,
        "historical_score": historical,
        "total_score":      total,
        "risk_level":       risk_level(total),
    }


def calculate_structural_risk(domain_data: Dict[str, Any]) -> int:
    """Convenience helper — returns the structural component (0–25)."""
    signals = [
        {"name": "young_domain",    "value": domain_data.get("young_domain")},
        {"name": "suspicious_tld",  "value": domain_data.get("suspicious_tld")},
        {"name": "high_entropy",    "value": domain_data.get("high_entropy")},
        {"name": "phishing_keyword","value": domain_data.get("phishing_keyword")},
    ]
    return _score_structural(signals)
