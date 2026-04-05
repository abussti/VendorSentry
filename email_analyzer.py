# email_analyzer.py

import re
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv
import os

load_dotenv()

KNOWN_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dhl", "fedex",
    "ups", "hsbc", "barclays", "emirates", "etisalat", "du"
]

BRAND_DISPLAY = {
    "paypal": "PayPal", "microsoft": "Microsoft",
    "google": "Google", "apple": "Apple",
    "amazon": "Amazon", "netflix": "Netflix",
    "facebook": "Facebook", "linkedin": "LinkedIn",
    "instagram": "Instagram", "twitter": "Twitter",
    "dhl": "DHL", "fedex": "FedEx", "ups": "UPS",
    "hsbc": "HSBC", "barclays": "Barclays",
    "emirates": "Emirates", "etisalat": "Etisalat", "du": "Du"
}


URGENT_KEYWORDS = [
    "urgent", "immediately", "act now", "account suspended",
    "verify your account", "click here", "confirm your identity",
    "unusual activity", "limited time", "your account will be",
    "password expired", "security alert", "update your payment",
    "you have been selected", "congratulations", "wire transfer",
    "invoice attached", "overdue", "final notice"
]

# ── Extract sender domain ─────────────────────────────────────────────────────

def extract_domain(sender):
    sender = sender.strip().lower()
    if "@" in sender:
        return sender.split("@")[-1]
    return sender

# ── Brand impersonation ───────────────────────────────────────────────────────

def detect_impersonation(domain):
    hits = []
    for brand in KNOWN_BRANDS:
        if brand in domain and domain != f"{brand}.com" and not domain.endswith(f".{brand}.com"):
            hits.append(brand)
    return hits

# ── Content analysis ──────────────────────────────────────────────────────────

def analyze_content(subject, body):
    text = (subject + " " + body).lower()
    hits = [kw for kw in URGENT_KEYWORDS if kw in text]

    patterns = {
        "ip_in_url":        bool(re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)),
        "multiple_urls":    len(re.findall(r'https?://', text)) > 3,
        "urgency_keywords": len(hits) > 0,
        "suspicious_words": any(w in text for w in ["bitcoin", "crypto", "wire", "gift card", "winning"]),
        "excessive_caps":   sum(1 for c in subject if c.isupper()) > len(subject) * 0.4,
    }

    return {
        "keyword_hits":  hits,
        "pattern_flags": patterns,
        "flag_count":    sum(patterns.values()),
    }

# ── URL extraction ────────────────────────────────────────────────────────────

def extract_urls(body):
    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', body)
    return list(set(urls))

# ── URL reputation ────────────────────────────────────────────────────────────

def check_url_reputation(urls, vt_key):
    if not vt_key or not urls:
        return []

    results = []
    for url in urls[:5]:
        try:
            domain = re.sub(r'https?://', '', url).split('/')[0]
            r = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": vt_key},
                timeout=10
            )
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                results.append({
                    "url":        url,
                    "domain":     domain,
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                })
        except Exception as e:
            results.append({"url": url, "error": str(e)})

    return results


# ── Domain age check ──────────────────────────────────────────────────────────

def check_domain_age(domain):
    """Check domain registration age as a phishing indicator."""
    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age_days = (datetime.now(timezone.utc) - creation.replace(tzinfo=timezone.utc)).days
            if age_days < 30:
                return {"age_days": age_days, "label": "Newly registered (< 30 days) — high risk indicator", "risk": "High"}
            elif age_days < 180:
                return {"age_days": age_days, "label": f"Recently registered ({age_days} days old) — moderate risk", "risk": "Medium"}
            else:
                return {"age_days": age_days, "label": f"Established domain ({age_days} days old)", "risk": "Low"}
    except Exception:
        pass
    return {"age_days": None, "label": "Domain age unavailable (WHOIS lookup failed) — treated as suspicious", "risk": "Unknown"}


def analyze_email_headers(raw_headers):
    """
    Parse raw email headers for SPF, DKIM, DMARC alignment results.
    Accepts the raw Received/Authentication-Results header block as a string.
    """
    if not raw_headers:
        return {
            "spf":   {"result": "not_provided", "label": "Not provided"},
            "dkim":  {"result": "not_provided", "label": "Not provided"},
            "dmarc": {"result": "not_provided", "label": "Not provided"},
            "issues": [],
            "fail_count": 0,
            "status": "no_headers"
        }

    headers_lower = raw_headers.lower()
    issues = []

    # SPF
    if "spf=pass" in headers_lower:
        spf = {"result": "pass", "label": "Pass — sender IP authorised"}
    elif "spf=fail" in headers_lower:
        spf = {"result": "fail", "label": "FAIL — sender IP not authorised"}
        issues.append("SPF FAIL — email may be spoofed")
    elif "spf=softfail" in headers_lower:
        spf = {"result": "softfail", "label": "Softfail — sender IP not fully authorised"}
        issues.append("SPF Softfail — weak authorisation")
    elif "spf=neutral" in headers_lower:
        spf = {"result": "neutral", "label": "Neutral — no SPF policy enforced"}
    else:
        spf = {"result": "none", "label": "Not found in headers"}
        issues.append("SPF result missing from headers")

    # DKIM
    if "dkim=pass" in headers_lower:
        dkim = {"result": "pass", "label": "Pass — message signature verified"}
    elif "dkim=fail" in headers_lower:
        dkim = {"result": "fail", "label": "FAIL — signature verification failed"}
        issues.append("DKIM FAIL — message may have been tampered with")
    elif "dkim=none" in headers_lower or "dkim" not in headers_lower:
        dkim = {"result": "none", "label": "Not signed — no DKIM signature present"}
        issues.append("No DKIM signature — sender identity unverified")
    else:
        dkim = {"result": "unknown", "label": "Unknown result"}

    # DMARC
    if "dmarc=pass" in headers_lower:
        dmarc = {"result": "pass", "label": "Pass — email aligned with domain policy"}
    elif "dmarc=fail" in headers_lower:
        dmarc = {"result": "fail", "label": "FAIL — email failed DMARC policy"}
        issues.append("DMARC FAIL — high confidence spoofing or phishing attempt")
    elif "dmarc=none" in headers_lower or "dmarc" not in headers_lower:
        dmarc = {"result": "none", "label": "No DMARC policy found"}
        issues.append("No DMARC result — domain policy not enforced")
    else:
        dmarc = {"result": "unknown", "label": "Unknown result"}

    # Overall header verdict
    fail_count = sum(1 for x in [spf, dkim, dmarc] if x["result"] in ("fail", "none", "not_provided"))

    return {
        "spf":        spf,
        "dkim":       dkim,
        "dmarc":      dmarc,
        "issues":     issues,
        "fail_count": fail_count,
        "status":     "analysed"
    }


# ── Threat intelligence summary ───────────────────────────────────────────────

def build_threat_intel_summary(vt_result, dns, ssl, hibp, impersonation_hits=None, domain_age=None):
    """Build a structured threat intel summary for display and AI injection."""
    intel = []

    # Domain highlight
    if impersonation_hits:
        intel.append(f"Suspicious Domain — impersonating '{BRAND_DISPLAY.get(impersonation_hits[0], impersonation_hits[0].title())}' (likely fraudulent registration)")

    malicious = vt_result.get("malicious", 0)
    if malicious > 0:
        total_engines = malicious + vt_result.get("suspicious", 0) + vt_result.get("harmless", 0) + vt_result.get("undetected", 0)
        total_engines = total_engines if total_engines > 0 else 70
        intel.append(f"VirusTotal — {malicious}/{total_engines} engines flagged domain as malicious")
    else:
        intel.append(f"VirusTotal — {vt_result.get('harmless', 0)} engines report clean, no malicious flags")


    if not dns.get("has_spf"):
        intel.append("DNS — Missing SPF record (email origin unverifiable)")
    if not dns.get("has_dmarc"):
        intel.append("DNS — Missing DMARC record (domain spoofing possible)")
    if not dns.get("has_mx"):
        intel.append("DNS — No MX records (domain not configured for email)")

    if not ssl.get("valid"):
        intel.append("SSL — Certificate invalid or domain not reachable (inactive/suspicious infrastructure)")
    elif ssl.get("days_remaining", 999) < 30:
        intel.append(f"SSL — Certificate expires in {ssl.get('days_remaining')} days")

    if hibp.get("breach_count", 0) > 0:
        intel.append(f"HIBP — {hibp['breach_count']} known breach(es) on sender domain")

    if domain_age and domain_age.get("risk") in ("High", "Medium"):
        intel.append(f"Domain Age — {domain_age['label']}")

    seen = set()
    clean = []
    for item in intel:
        if item not in seen:
            clean.append(item)
            seen.add(item)
    return clean

# ── Risk factor explanations ──────────────────────────────────────────────────

def build_risk_factors(content_analysis, url_results, sender_domain_findings, impersonation_hits, header_analysis=None):
    factors = []
    flags = content_analysis.get("pattern_flags", {})

    if flags.get("urgency_keywords"):
        factors.append("Urgency language detected — pressures recipient into acting without thinking")
    if flags.get("ip_in_url"):
        factors.append("IP-based URL found — hides real destination, a hallmark of phishing infrastructure")
    if flags.get("multiple_urls"):
        factors.append("Multiple URLs in body — increases attack surface")
    if flags.get("suspicious_words"):
        factors.append("High-risk financial keywords detected — common in fraud and scam emails")
    if flags.get("excessive_caps"):
        factors.append("Excessive capitalisation in subject line — psychological pressure tactic")
    if impersonation_hits:
        brand_name = BRAND_DISPLAY.get(impersonation_hits[0], impersonation_hits[0].title())
        factors.append(f"Brand impersonation detected — domain mimics '{brand_name}' to appear legitimate")

    malicious_urls = [r for r in url_results if r.get("malicious", 0) > 0]
    if malicious_urls:
        factors.append(f"{len(malicious_urls)} URL(s) flagged as malicious by VirusTotal threat intelligence")

    dns = sender_domain_findings.get("dns", {})
    ssl = sender_domain_findings.get("ssl", {})

    if not dns.get("has_spf"):
        factors.append("Sender domain missing SPF record — sender authenticity cannot be verified")
    if not dns.get("has_dmarc"):
        factors.append("Sender domain missing DMARC record — domain spoofing is possible")
    if not ssl.get("valid"):
        factors.append("Sender domain has no valid SSL certificate — domain likely inactive or not legitimately configured")

    if header_analysis and header_analysis.get("status") == "analysed":
        for issue in header_analysis.get("issues", []):
            factors.append(f"Header auth failure: {issue}")

    return factors

def build_top_risk_drivers(impersonation_hits, vt_result, dns, ssl, content_analysis):
    """Build top 3 risk drivers for executive summary display."""
    drivers = []

    vt_malicious = vt_result.get("malicious", 0)
    total_engines = vt_malicious + vt_result.get("harmless", 0) + vt_result.get("suspicious", 0)
    total_engines = total_engines if total_engines > 0 else 70

    if impersonation_hits:
        brand_display = {"paypal": "PayPal", "microsoft": "Microsoft",
                         "google": "Google", "apple": "Apple",
                         "amazon": "Amazon", "netflix": "Netflix",
                         "facebook": "Facebook", "linkedin": "LinkedIn",
                         "instagram": "Instagram", "twitter": "Twitter",
                         "dhl": "DHL", "fedex": "FedEx", "ups": "UPS",
                         "hsbc": "HSBC", "barclays": "Barclays",
                         "emirates": "Emirates", "etisalat": "Etisalat", "du": "Du"}
        brand_name = brand_display.get(impersonation_hits[0], impersonation_hits[0].title())
        drivers.append(f"Brand impersonation ({brand_name})")
    if vt_malicious > 0:
        drivers.append(f"{vt_malicious}/{total_engines} VirusTotal engines flagged domain as malicious")
    if not dns.get("has_spf") and not dns.get("has_dmarc"):
        drivers.append("Missing SPF + DMARC — sender authenticity cannot be verified")
    elif not dns.get("has_spf"):
        drivers.append("Missing SPF record — sender authenticity cannot be verified")
    elif not dns.get("has_dmarc"):
        drivers.append("Missing DMARC — domain spoofing possible")
    if not ssl.get("valid"):
        drivers.append("Invalid SSL certificate — domain not legitimately configured")

    keywords = content_analysis.get("keyword_hits", [])
    if len(keywords) >= 5:
        drivers.append(f"{len(keywords)} phishing keywords detected in email body")

    flags = content_analysis.get("pattern_flags", {})
    if flags.get("ip_in_url"):
        drivers.append("IP-based URL — hides real destination")

    return drivers[:3]


# ── Scoring ───────────────────────────────────────────────────────────────────

def score_email(content_analysis, url_results, sender_domain_findings, sender_domain_scores, impersonation_hits):
    threat = 0

    flag_count = content_analysis.get("flag_count", 0)
    threat += min(flag_count * 8, 30)

    keyword_hits = len(content_analysis.get("keyword_hits", []))
    threat += min(keyword_hits * 4, 20)

    malicious_urls = sum(r.get("malicious", 0) for r in url_results if "malicious" in r)
    if malicious_urls > 0:
        threat += 25

    if impersonation_hits:
        threat += 20

    if sender_domain_scores:
        domain_score  = sender_domain_scores.get("total", 100)
        domain_threat = (100 - domain_score) * 0.15
        threat += domain_threat

    dns = sender_domain_findings.get("dns", {})
    if not dns.get("has_spf"):
        threat += 5
    if not dns.get("has_dmarc"):
        threat += 5

    email_threat = min(round(threat), 100)

    domain_total        = sender_domain_scores.get("total", 50) if sender_domain_scores else 50
    domain_threat_score = 100 - domain_total
    final_score         = min(round((email_threat * 0.7) + (domain_threat_score * 0.3)), 100)

    return email_threat, final_score

# ── Risk label with nuance ────────────────────────────────────────────────────

def risk_label(score):
    if score >= 70:
        return "High"
    elif score >= 55:
        return "Medium-High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"

# ── Verdict reason builder ────────────────────────────────────────────────────

def build_verdict_reason(impersonation_hits, vt_malicious, dns, ssl):
    """Build a short multi-source reason string for the verdict."""
    sources = []
    if vt_malicious > 0:
        sources.append(f"VirusTotal ({vt_malicious} malicious flags)")
    if impersonation_hits:
        sources.append(f"Brand impersonation ({BRAND_DISPLAY.get(impersonation_hits[0], impersonation_hits[0].title())})")
    if not dns.get("has_spf") or not dns.get("has_dmarc"):
        sources.append("DNS security failures")
    if not ssl.get("valid"):
        sources.append("Invalid SSL certificate")

    if sources:
        return "Multiple independent threat indicators: " + " + ".join(sources)
    return "Elevated risk indicators detected across analysis sources"

# ── AI summary ────────────────────────────────────────────────────────────────

def generate_email_summary(sender, subject, content_analysis, url_results,
                            sender_domain_scores, sender_domain_findings,
                            email_threat, final_score, impersonation_hits,
                            risk_factors, attack_type, threat_intel):
    try:
        email_threat = int(email_threat) if email_threat else 0
        final_score  = int(final_score)  if final_score  else 0
        email_risk   = risk_label(email_threat)
        final_risk   = risk_label(final_score)
        keywords   = content_analysis.get("keyword_hits", [])
        flags      = content_analysis.get("pattern_flags", {})
        malicious  = [r for r in url_results if r.get("malicious", 0) > 0]
        dns        = sender_domain_findings.get("dns", {})
        ssl        = sender_domain_findings.get("ssl", {})
        vt         = sender_domain_findings.get("virustotal", {})


        vt_malicious = vt.get('malicious', 0)
        vt_total     = vt_malicious + vt.get('harmless', 0) + vt.get('suspicious', 0) + vt.get('undetected', 0)
        vt_total     = vt_total if vt_total > 0 else 70
        vt_string    = f"{vt_malicious} out of {vt_total} VirusTotal engines flagged the domain as malicious"

        prompt = f"""
You are a senior cybersecurity analyst writing a threat assessment for a SOC team.

Email threat score: {str(email_threat)}/100 ({str(email_risk)} Risk)
Final combined risk score: {str(final_score)}/100 ({str(final_risk)} Risk)
Attack classification: {str(attack_type)}

MANDATORY: Copy this exact sentence into your summary without changing any numbers:
"{vt_string}"

Confirmed findings:
{chr(10).join(f"- {item}" for item in threat_intel)}
- Brand impersonation: {impersonation_hits if impersonation_hits else 'None detected'}
- Phishing keywords: {keywords if keywords else 'None'}
- IP-based URL: {flags.get('ip_in_url', False)}
- Sender SPF: {'Present' if dns.get('has_spf') else 'MISSING'}
- Sender DMARC: {'Present' if dns.get('has_dmarc') else 'MISSING'}
- Sender SSL: {'Valid' if ssl.get('valid') else 'Invalid or missing'}

Write exactly 2 short paragraphs for a SOC analyst.
Paragraph 1: Threat indicators. Use the mandatory sentence above word for word.
Paragraph 2: Recommended response — block domain at email gateway, report to abuse channel, notify affected users.
No bullet points. No apostrophes around domain names. Under 120 words total.
"""

        r = requests.post("http://localhost:11434/api/generate", json={
            "model": "phi3:mini",
            "prompt": prompt,
            "stream": False
        }, timeout=300)

        if r.status_code == 200:
            response = r.json().get("response", "").strip()
            # Truncate at common LLM hallucination triggers
            for cutoff in ["Your task:", "Task:", "Note:", "Example:", "---", "Exercise:", "As the head"]:
                if cutoff in response:
                    response = response[:response.index(cutoff)].strip()
            return response
        return "AI summary unavailable."

    except Exception as e:
        return f"AI summary unavailable: {str(e)}"

# ── Master analysis function ──────────────────────────────────────────────────

def analyze_email(sender, subject, body, raw_headers=None,  vt_key=None, shodan_key=None, hibp_key=None):
    print(f"\n{'='*50}")
    print(f"  Analyzing email from: {sender}")
    print(f"{'='*50}\n")

    sender_domain = extract_domain(sender)
    print(f"[*] Sender domain: {sender_domain}")

    impersonation_hits = detect_impersonation(sender_domain)
    if impersonation_hits:
        brand = impersonation_hits[0]
        safe_action = (
            f"Do not click any links. "
            f"Block sender domain '{sender_domain}' at your email gateway. "
            f"Report to abuse@{brand}.com and forward to your security team. "
            f"Warn users who may have received this email. "
            f"Verify directly at https://www.{brand}.com if account action is needed."
        )
    else:
        safe_action = (
            f"Do not reply or click any links. "
            f"Block sender domain '{sender_domain}' at your email gateway. "
            f"Forward to your security team for investigation. "
            f"If the email claims to be from a known service, verify directly via their official website."
        )

    print("[*] Checking domain age...")
    domain_age = check_domain_age(sender_domain)
    print(f"[+] Domain age: {domain_age['label']}")

    print("[*] Analyzing email headers...")
    header_analysis = analyze_email_headers(raw_headers)
    if header_analysis["fail_count"] > 0:
        print(f"[!] {header_analysis['fail_count']} header authentication failure(s) detected")
    else:
        print(f"[+] Header analysis: {header_analysis['status']}")

    print("[*] Analyzing email content for phishing indicators...")
    content_analysis = analyze_content(subject, body)
    print(f"[+] Content flags: {content_analysis['flag_count']}, Keywords: {len(content_analysis['keyword_hits'])}")

    urls = extract_urls(body)
    print(f"[*] Extracted {len(urls)} URL(s) from body")
    url_results = check_url_reputation(urls, vt_key)

    malicious_url_count = sum(r.get("malicious", 0) for r in url_results if "malicious" in r)
    if malicious_url_count > 0:
        print(f"[!] {malicious_url_count} malicious URL(s) detected by VirusTotal")

    print(f"[*] Running vendor risk scan on sender domain: {sender_domain}")
    from scanner import run_scan
    from scorer import run_scoring
    sender_domain_findings = run_scan(sender_domain, shodan_key=shodan_key,
                                      vt_key=vt_key, hibp_key=hibp_key)
    sender_domain_scores = run_scoring(sender_domain_findings)

    dns  = sender_domain_findings.get("dns", {})
    ssl  = sender_domain_findings.get("ssl", {})
    vt   = sender_domain_findings.get("virustotal", {})
    hibp = sender_domain_findings.get("hibp", {})

    # Build structured threat intel summary
    threat_intel = build_threat_intel_summary(vt, dns, ssl, hibp, impersonation_hits, domain_age)

    risk_factors = build_risk_factors(
        content_analysis, url_results, sender_domain_findings, impersonation_hits, header_analysis
    )

    top_drivers = build_top_risk_drivers(
        impersonation_hits, vt, dns, ssl, content_analysis
    )

    email_threat, final_score = score_email(
        content_analysis, url_results,
        sender_domain_findings, sender_domain_scores, impersonation_hits
    )

    # Critical signal override — mirrors real-world threat scoring systems
    vt_malicious = vt.get("malicious", 0)
    if vt_malicious >= 10 and impersonation_hits:
        final_score = max(final_score, 80)
        email_threat = max(email_threat, 75)
        print(f"[!] Critical signal override applied — VT {vt_malicious} hits + impersonation")

    email_risk = risk_label(email_threat)
    final_risk = risk_label(final_score)
    confidence = min(70 + (len(risk_factors) * 4), 95)

    # Verdict
    if final_score >= 70 or (impersonation_hits and email_threat >= 50):
        verdict = "Likely Phishing — Do Not Interact"
        verdict_level = "High"
    elif final_score >= 40:
        verdict = "Suspicious — Treat With Caution"
        verdict_level = "Medium"
    else:
        verdict = "Low Risk — Appears Legitimate"
        verdict_level = "Low"

    # Verdict reason (multi-source)
    verdict_reason = build_verdict_reason(
        impersonation_hits, vt.get("malicious", 0), dns, ssl
    )

    # Attack type classification
    flags = content_analysis.get("pattern_flags", {})
    if impersonation_hits and flags.get("urgency_keywords"):
        attack_type = "Phishing — Credential Harvesting"
    elif flags.get("suspicious_words"):
        attack_type = "Fraud — Financial Scam"
    elif flags.get("ip_in_url") or malicious_url_count > 0:
        attack_type = "Phishing — Malware Delivery"
    elif flags.get("urgency_keywords"):
        attack_type = "Social Engineering — Urgency Manipulation"
    else:
        attack_type = "Suspicious — Unclassified"

    # Safe action
    safe_action = None
    for brand in KNOWN_BRANDS:
        if brand in sender_domain:
            safe_action = f"Manually visit https://www.{brand}.com directly — do not click any links in this email"
            break
    if not safe_action:
        safe_action = "Contact the organisation directly via their official website — do not reply to this email"

    print(f"[+] Verdict: {verdict}")
    print(f"[+] Reason: {verdict_reason}")
    print(f"[+] Attack type: {attack_type}")
    print(f"[+] Email threat score: {email_threat}/100 ({email_risk} Risk)")
    print(f"[+] Final combined score: {final_score}/100 ({final_risk} Risk)")
    print(f"[+] Confidence: {confidence}%")
    print(f"\n[*] Threat Intelligence Summary:")
    for item in threat_intel:
        print(f"    - {item}")

    print("[*] Generating AI summary...")
    ai_summary = generate_email_summary(
        sender, subject, content_analysis, url_results,
        sender_domain_scores, sender_domain_findings,
        email_threat, final_score, impersonation_hits,
        risk_factors, attack_type, threat_intel
    )


    return {
        "analyzed_at":            datetime.now(timezone.utc).isoformat(),
        "sender":                 sender,
        "sender_domain":          sender_domain,
        "subject":                subject,
        "email_threat_score":     email_threat,
        "email_risk_level":       email_risk,
        "final_score":            final_score,
        "final_risk_level":       final_risk,
        "confidence":             confidence,
        "verdict":                verdict,
        "verdict_level":          verdict_level,
        "verdict_reason":         verdict_reason,
        "attack_type":            attack_type,
        "impersonation_hits":     impersonation_hits,
        "risk_factors":           risk_factors,
        "threat_intel":           threat_intel,
        "safe_action":            safe_action,
        "content_analysis":       content_analysis,
        "urls_found":             urls,
        "url_reputation":         url_results,
        "sender_domain_score":    sender_domain_scores.get("total"),
        "sender_domain_risk":     sender_domain_scores.get("risk_level"),
        "sender_domain_findings": sender_domain_findings,
        "ai_summary":             ai_summary,
        "domain_age": domain_age,
        "header_analysis": header_analysis,
        "top_drivers": top_drivers,
    }


if __name__ == "__main__":
    import json
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Email Threat Analyzer")
    parser.add_argument("input", nargs="?", help="Email file to analyze (batch mode)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--sender",  default="support@paypal-security-update.com")
    parser.add_argument("--subject", default="URGENT: Your account has been suspended - Act Now")
    parser.add_argument("--body",    default="""
        Dear Customer,
        We have detected unusual activity on your account.
        You must verify your account immediately or it will be suspended.
        Click here to confirm your identity: http://192.168.1.1/verify
        Your password has expired. Act now to avoid losing access.
        This is a final notice.
        PayPal Security Team
    """)
    args = parser.parse_args()

    # Batch mode
    if args.input:
        try:
            with open(args.input, "r") as f:
                emails = json.load(f)
            results = []
            for email in emails:
                r = analyze_email(
                    sender=email.get("sender"),
                    subject=email.get("subject"),
                    body=email.get("body"),
                    vt_key=os.environ.get("VT_API_KEY"),
                    shodan_key=os.environ.get("SHODAN_API_KEY"),
                    hibp_key=os.environ.get("HIBP_API_KEY")
                )
                results.append(r)
            if args.json:
                print(json.dumps(results, indent=2, default=str))
            else:
                for r in results:
                    print(f"\n{r['sender']} — {r['verdict']} — {r['final_score']}/100")
        except Exception as e:
            print(f"[-] Batch mode error: {e}")
        sys.exit(0)

    # Single email mode
    result = analyze_email(
        sender=args.sender,
        subject=args.subject,
        body=args.body,
        vt_key=os.environ.get("VT_API_KEY"),
        shodan_key=os.environ.get("SHODAN_API_KEY"),
        hibp_key=os.environ.get("HIBP_API_KEY")
    )

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"\n── Email Analysis Result ─────────────────────")
        print(f"Verdict:             {result['verdict']}")
        print(f"Reason:              {result['verdict_reason']}")
        print(f"Attack Type:         {result['attack_type']}")
        print(f"Email Threat Score:  {result['email_threat_score']}/100 ({result['email_risk_level']} Risk)")
        print(f"Final Score:         {result['final_score']}/100 ({result['final_risk_level']} Risk)")
        print(f"Confidence:          {result['confidence']}%")
        print(f"\nThreat Intelligence:")
        for item in result['threat_intel']:
            print(f"  - {item}")
        print(f"\nRisk Factors:")
        for f in result['risk_factors']:
            print(f"  - {f}")
        print(f"\nSafe Action: {result['safe_action']}")
        print(f"\nAI Summary:\n{result['ai_summary']}")
