from typing import List, Dict, Any


def score(signals: List[Dict[str, Any]]) -> Dict[str, int]:
    """Deterministic weighted scoring model.

    Categories have maximum contributions:
        structural: 40
        vt: 30
        ioc: 30

    Signals may add weights or values; this simple model looks at
    a few known signal names and computes scores accordingly.  Later
    this function can be replaced by an ML model.
    """
    structural = 0
    vt = 0
    ioc = 0

    for signal in signals:
        name = signal.get("name")
        v = signal.get("value")
        # example rules
        if name == "domain_length":
            # longer domains are more suspicious
            structural += min(len(str(v)), 40)
        elif name == "vt_malicious":
            # each malicious detection adds weight
            vt += min(v * 5, 30)
        elif name == "ioc_match":
            if v:
                ioc += 30
        elif name == "suspicious_tld":
            structural += 10
        elif name == "ip_domain":
            structural += 20
        # add other signal handlers as needed

    # clamp values
    structural = min(structural, 40)
    vt = min(vt, 30)
    ioc = min(ioc, 30)
    total = structural + vt + ioc

    return {
        "structural_score": structural,
        "vt_score": vt,
        "ioc_score": ioc,
        "total_score": total,
    }
