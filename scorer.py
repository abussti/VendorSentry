# scorer.py

from datetime import datetime, timezone

WEIGHTS = {
    "breach":   0.25,
    "exposure": 0.25,
    "vuln":     0.20,
    "dns":      0.15,
    "ssl":      0.15,
}

# ── Known brand names for impersonation detection ─────────────────────────────

KNOWN_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dhl", "fedex",
    "ups", "hsbc", "barclays", "emirates", "etisalat", "du",
    "visa", "mastercard", "chase", "wellsfargo", "bankofamerica"
]

# ── Known test / lab domains (should not score as safe) ───────────────────────

KNOWN_TEST_DOMAINS = [
    "vulnweb.com", "testphp.vulnweb.com", "testaspnet.vulnweb.com",
    "testhtml5.vulnweb.com", "wicar.org", "eicar.org",
    "hackthissite.org", "dvwa.co.uk", "webscantest.com"
]

# ── Scoring functions ─────────────────────────────────────────────────────────

def score_breach(hibp, virustotal):
    score = 100

    breach_count = hibp.get("breach_count", 0)
    if breach_count >= 3:
        score -= 60
    elif breach_count >= 1:
        score -= 35

    malicious  = virustotal.get("malicious", 0)
    suspicious = virustotal.get("suspicious", 0)
    if malicious >= 10:
        score -= 50
    elif malicious >= 5:
        score -= 40
    elif malicious >= 1:
        score -= 25
    if suspicious >= 3:
        score -= 15

    return max(score, 0)


def score_exposure(shodan):
    score = 100
    open_ports = shodan.get("open_ports", [])
    vuln_count = len(shodan.get("vulns", []))

    dangerous = {21, 23, 3389, 445, 139, 5900, 6379, 27017, 9200}
    risky     = {22, 25, 80, 8080, 8443, 3306, 5432}

    for port in open_ports:
        if port in dangerous:
            score -= 20
        elif port in risky:
            score -= 8

    if vuln_count >= 5:
        score -= 30
    elif vuln_count >= 1:
        score -= 15

    return max(score, 0)


def score_vuln(nvd_cves):
    # No CVEs found does NOT mean safe — treat as unknown (neutral baseline 75)
    if not nvd_cves:
        return 75

    score = 100
    critical = [c for c in nvd_cves if c.get("score") and c["score"] >= 9.0]
    high     = [c for c in nvd_cves if c.get("score") and 7.0 <= c["score"] < 9.0]
    medium   = [c for c in nvd_cves if c.get("score") and 4.0 <= c["score"] < 7.0]

    score -= len(critical) * 25
    score -= len(high)     * 15
    score -= len(medium)   * 5

    return max(score, 0)


def score_dns(dns):
    score = 100

    if not dns.get("has_spf"):
        score -= 25
    if not dns.get("has_dmarc"):
        score -= 25
    if not dns.get("has_mx"):
        score -= 15
    if not dns.get("a_records"):
        score -= 20

    score -= max(0, len(dns.get("issues", [])) - 1) * 5

    return max(score, 0)


def score_ssl(ssl):
    score = 100

    if not ssl.get("valid"):
        return 0

    if ssl.get("expired"):
        score -= 60

    days = ssl.get("days_remaining", 999)
    if days < 7:
        score -= 40
    elif days < 30:
        score -= 20
    elif days < 60:
        score -= 10

    score -= len(ssl.get("issues", [])) * 10

    return max(score, 0)


def infrastructure_legitimacy(dns, ssl, findings):
    """
    Score whether this domain looks like a real legitimate vendor.
    Missing infrastructure = suspicious, not safe.
    Returns a penalty (0 = no penalty, higher = more suspicious).
    """
    flags = []

    if not dns.get("a_records"):
        flags.append("No A record — domain does not resolve")
    if not dns.get("has_mx"):
        flags.append("No MX record — domain not configured for email")
    if not ssl.get("valid"):
        flags.append("No valid SSL — not configured as a legitimate service")
    if not dns.get("has_spf") and not dns.get("has_dmarc"):
        flags.append("No email authentication — SPF and DMARC both missing")

    vt_malicious = findings.get("virustotal", {}).get("malicious", 0)
    if vt_malicious >= 5:
        flags.append(f"VirusTotal: {vt_malicious} engines flagged as malicious")

    return flags


def detect_impersonation(domain):
    """Check if domain contains a known brand name but is not the real domain."""
    for brand in KNOWN_BRANDS:
        if brand in domain and domain != f"{brand}.com" and not domain.endswith(f".{brand}.com"):
            return brand
    return None


def is_test_domain(domain):
    """Check if this is a known test/lab domain."""
    for test in KNOWN_TEST_DOMAINS:
        if test in domain:
            return True
    return False


def calculate_risk_level(total):
    if total < 40:
        return "High"
    elif total < 70:
        return "Medium"
    return "Low"


def run_scoring(findings):
    domain = findings.get("domain", "")
    dns    = findings.get("dns", {})
    ssl    = findings.get("ssl", {})

    scores = {
        "breach":   score_breach(findings.get("hibp", {}), findings.get("virustotal", {})),
        "exposure": score_exposure(findings.get("shodan", {})),
        "vuln":     score_vuln(findings.get("nvd", [])),
        "dns":      score_dns(dns),
        "ssl":      score_ssl(ssl),
    }

    total = round(sum(scores[k] * WEIGHTS[k] for k in WEIGHTS))

    # ── Override rules ────────────────────────────────────────────────────────

    infra_flags = infrastructure_legitimacy(dns, ssl, findings)
    impersonated_brand = detect_impersonation(domain)
    is_test = is_test_domain(domain)

    # Rule 1: Non-legitimate domain override
    # If domain has no DNS, no SSL, no MX → cap at 40 (High Risk)
    missing_count = sum([
        not dns.get("a_records"),
        not dns.get("has_mx"),
        not ssl.get("valid"),
        not dns.get("has_spf") and not dns.get("has_dmarc")
    ])
    if missing_count >= 3:
        total = min(total, 40)
        infra_flags.append("Domain lacks basic infrastructure — likely non-operational or malicious")

    # Rule 2: Brand impersonation override
    if impersonated_brand:
        total = min(total, 40)
        infra_flags.append(f"Brand impersonation detected — domain mimics '{impersonated_brand}'")

    # Rule 3: Combined override — impersonation + no DNS + no SSL = very high risk
    if impersonated_brand and not ssl.get("valid") and missing_count >= 2:
        total = min(total, 25)

    # Rule 4: Known test domain — apply moderate penalty
    if is_test:
        total = min(total, 55)
        infra_flags.append("Known test/lab domain — not a production vendor environment")

    # Rule 5: High VT malicious flags always push to high risk
    vt_malicious = findings.get("virustotal", {}).get("malicious", 0)
    if vt_malicious >= 10:
        total = min(total, 35)

    # ── Confidence weighting ──────────────────────────────────────────────────
    coverage    = findings.get("coverage", {})
    confidence  = coverage.get("confidence", "Unknown")
    active      = coverage.get("active", 0)
    total_src   = coverage.get("total", 5)

    # Adjust score slightly based on data completeness
    if confidence == "Low":
        # Less data = less certainty = nudge score toward middle
        total = round(total * 0.95)

    risk_level = calculate_risk_level(total)

    print(f"\n-- Risk Score Breakdown --")
    for k, v in scores.items():
        bar = "X" * (v // 10) + "." * (10 - v // 10)
        print(f"  {k:<10} {bar}  {v}/100")
    if infra_flags:
        print(f"\n  Override rules applied:")
        for flag in infra_flags:
            print(f"    ! {flag}")
    print(f"  {'TOTAL':<10} {'─'*22}  {total}/100  [{risk_level} Risk]")
    print(f"  {'CONFIDENCE':<10} {'─'*22}  {confidence} ({active}/{total_src} sources)")

    return {
        "total":        total,
        "breach":       scores["breach"],
        "exposure":     scores["exposure"],
        "vuln":         scores["vuln"],
        "dns":          scores["dns"],
        "ssl":          scores["ssl"],
        "risk_level":   risk_level,
        "confidence":   confidence,
        "coverage":     f"{active}/{total_src} sources active",
        "infra_flags":  infra_flags,
        "impersonation": impersonated_brand,
        "is_test_domain": is_test,
    }


if __name__ == "__main__":
    # Test with paypal-security-update.com data
    test_findings = {
        "domain": "paypal-security-update.com",
        "hibp":       {"breach_count": 0},
        "virustotal": {"malicious": 13, "suspicious": 0},
        "shodan":     {"open_ports": [], "vulns": []},
        "nvd":        [],
        "dns": {
            "has_spf": False, "has_dmarc": False,
            "has_mx": False, "a_records": [], "issues": []
        },
        "ssl": {"valid": False, "expired": False, "days_remaining": None, "issues": []},
        "coverage": {"confidence": "Medium", "active": 3, "total": 5}
    }
    scores = run_scoring(test_findings)
    print(f"\nFinal: {scores['total']}/100 [{scores['risk_level']} Risk]")
