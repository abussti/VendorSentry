# llm.py

import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "gemma2:2b"

def generate_summary(domain, scores, findings):
    breach_info = findings.get("hibp", {})
    dns_info    = findings.get("dns", {})
    ssl_info    = findings.get("ssl", {})
    shodan_info = findings.get("shodan", {})
    nvd_info    = findings.get("nvd", [])
    vt_info     = findings.get("virustotal", {})

    prompt = f"""
You are a cybersecurity analyst conducting an EXTERNAL vendor risk assessment.
You are evaluating {domain} as a third-party supplier — you do not control their infrastructure.

Assessment results:
- Overall score: {scores['total']}/100 ({scores['risk_level']} Risk)
- Important: Always write the vendor name with correct capitalisation e.g. GitHub not Github, PayPal not Paypal
- Breach history score: {scores['breach']}/100
- DNS/email security score: {scores['dns']}/100
- SSL/TLS score: {scores['ssl']}/100
- Exposure score: {scores['exposure']}/100
- CVEs found: {len(findings.get('nvd', []))} (keyword-based, historical, require verification)
- Open ports detected: {findings.get('shodan', {}).get('open_ports', [])}
- VirusTotal malicious flags: {findings.get('virustotal', {}).get('malicious', 0)}
- SPF configured: {findings.get('dns', {}).get('has_spf', False)}
- DMARC configured: {findings.get('dns', {}).get('has_dmarc', False)}
- SSL valid: {findings.get('ssl', {}).get('valid', False)}

Important rules:
- No open ports found means the attack surface is limited — this is GOOD, not a concern
- CVEs are keyword-based and historical — do not present them as confirmed active vulnerabilities
- You cannot control the vendor's internal systems — recommendations must be from the BUYER's perspective
- Only comment on findings that are actually present
- Do not invent issues that are not in the data above

Write 2 short paragraphs for a security manager.
Paragraph 1: Overall risk posture based only on actual findings above.
Paragraph 2: Three realistic recommendations from the BUYER perspective — things like continuous monitoring, reviewing vendor security advisories, enforcing MFA on vendor accounts, contractual security requirements.
No bullet points. Under 120 words total.
- If no open ports were found, write: "No externally exposed services were identified during this assessment, suggesting a limited observable attack surface." Do not treat this as a concern.
"""


    print("[*] Generating AI summary via Ollama...")
    try:
        r = requests.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        }, timeout=300)

        if r.status_code == 200:
            summary = r.json().get("response", "").strip()
            print("[+] AI summary generated successfully")
            return summary
        else:
            print(f"[-] Ollama returned status {r.status_code}")
            return "AI summary unavailable."

    except requests.exceptions.ConnectionError:
        print("[-] Ollama not running. Start it with: ollama serve")
        return "AI summary unavailable — Ollama service not running."
    except Exception as e:
        print(f"[-] LLM error: {e}")
        return "AI summary unavailable."


if __name__ == "__main__":
    # Test with github.com data
    test_scores = {
        "total": 95,
        "breach": 100,
        "exposure": 100,
        "vuln": 75,
        "dns": 100,
        "ssl": 100,
        "risk_level": "Low"
    }

    test_findings = {
        "hibp":       {"breach_count": 0},
        "virustotal": {"malicious": 0},
        "shodan":     {"open_ports": []},
        "nvd":        [
            {"id": "CVE-2012-2055", "score": 7.5},
            {"id": "CVE-2012-5814", "score": 5.8},
        ],
        "dns": {
            "has_spf": True,
            "has_dmarc": True,
            "issues": []
        },
        "ssl": {
            "valid": True,
            "days_remaining": 63,
            "issues": []
        },
        "virustotal": {"malicious": 0}
    }

    summary = generate_summary("github.com", test_scores, test_findings)
    print(f"\n── AI Summary ────────────────────────────────\n")
    print(summary)
