from typing import Dict, Any

from app.services import ioc_service, vt_service, risk_engine


def analyze(target_url: str) -> Dict[str, Any]:
    """Perform full domain analysis and return structured result.

    Steps:
    1. Normalize URL and extract domain.
    2. Generate structural signals.
    3. Query IOC service for matches.
    4. Query VT service for reputation counts.
    5. Send signals to risk engine to compute scores.
    6. Return dictionary containing scores, signals and raw data.
    """
    # normalization (very simple placeholder)
    normalized = target_url.strip().lower()
    # extract domain (naive)
    domain = normalized.split("//")[-1].split("/")[0]

    structural_signals = {
        "domain_length": len(domain),
        # more signals added later
    }

    ioc_result = ioc_service.check_domain(domain)
    vt_result = vt_service.lookup_domain(domain)

    # build list of signals for risk engine
    signals = []
    # structural
    for name, val in structural_signals.items():
        signals.append({"name": name, "weight": 1, "value": val})
    # vt signals weight assigned in vt_service or risk engine
    signals.append({"name": "vt_malicious", "weight": 1, "value": vt_result.get("malicious")})
    # ioc signals
    if ioc_result.get("matched_ioc"):
        signals.append({"name": "ioc_match", "weight": 1, "value": True})

    score = risk_engine.score(signals)

    return {
        "domain": domain,
        "signals": structural_signals,
        "ioc": ioc_result,
        "vt": vt_result,
        "score": score,
    }
