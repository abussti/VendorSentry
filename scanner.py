#scanner.py
from dotenv import load_dotenv
load_dotenv()
import requests
import dns.resolver
import ssl
import socket
import json
from datetime import datetime, timezone

# ── crt.sh: subdomain discovery ──────────────────────────────────────────────

def get_subdomains(domain):
    print(f"[*] Discovering subdomains for {domain} via crt.sh...")
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20,
            headers={"Accept": "application/json"}
        )
        if r.status_code != 200:
            print(f"[-] crt.sh returned status {r.status_code}, skipping")
            return {"status": "failed", "reason": f"crt.sh returned {r.status_code}", "count": 0, "subdomains": []}

        text = r.text.strip()
        if not text or not text.startswith("["):
            print("[-] crt.sh returned unexpected response, skipping")
            return {"status": "failed", "reason": "unexpected response from crt.sh", "count": 0, "subdomains": []}

        data = r.json()
        subs = set()
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.split("\n"):
                line = line.strip().lstrip("*.")
                if "@" in line:
                    continue
                if line.startswith("http"):
                    continue
                if not line.endswith(domain):
                    continue
                if line == domain:
                    continue
                subs.add(line)

        print(f"[+] Found {len(subs)} subdomains")
        return {"status": "ok", "reason": None, "count": len(subs), "subdomains": list(subs)}

    except Exception as e:
        print(f"[-] crt.sh failed: {e}")
        return {"status": "failed", "reason": str(e), "count": 0, "subdomains": []}

# ── DNS checks ────────────────────────────────────────────────────────────────

def check_dns(domain):
    print(f"[*] Checking DNS records for {domain}...")
    results = {
        "has_spf": False,
        "has_dmarc": False,
        "has_mx": False,
        "spf_record": None,
        "dmarc_record": None,
        "mx_records": [],
        "a_records": [],
        "issues": []
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # A records
    try:
        answers = resolver.resolve(domain, "A")
        results["a_records"] = [r.address for r in answers]
    except Exception:
        results["issues"].append("No A record found")

    # MX records
    try:
        answers = resolver.resolve(domain, "MX")
        results["mx_records"] = [r.exchange.to_text() for r in answers]
        results["has_mx"] = True
    except Exception:
        results["issues"].append("No MX record - email not configured")

    # SPF (TXT record)
    try:
        answers = resolver.resolve(domain, "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if txt.startswith("v=spf1"):
                results["has_spf"] = True
                results["spf_record"] = txt
        if not results["has_spf"]:
            results["issues"].append("Missing SPF record")
    except Exception:
        results["issues"].append("Could not retrieve TXT records")

    # DMARC
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if "v=DMARC1" in txt:
                results["has_dmarc"] = True
                results["dmarc_record"] = txt
        if not results["has_dmarc"]:
            results["issues"].append("Missing DMARC record")
    except Exception:
        results["issues"].append("Missing DMARC record")

    print(f"[+] DNS issues found: {len(results['issues'])}")
    return results

# ── SSL/TLS check ─────────────────────────────────────────────────────────────

def check_ssl(domain):
    print(f"[*] Checking SSL certificate for {domain}...")
    results = {
        "valid": False,
        "expired": False,
        "days_remaining": None,
        "issuer": None,
        "issues": []
    }

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.socket(), server_hostname=domain
        ) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

        expire_str = cert["notAfter"]
        expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_remaining = (expire_date - datetime.now(timezone.utc)).days

        results["valid"] = True
        results["days_remaining"] = days_remaining
        results["issuer"] = dict(x[0] for x in cert.get("issuer", []))

        if days_remaining < 0:
            results["expired"] = True
            results["issues"].append("SSL certificate is expired")
        elif days_remaining < 30:
            results["issues"].append(f"SSL certificate expires in {days_remaining} days")

        print(f"[+] SSL valid, {days_remaining} days remaining")

    except ssl.SSLCertVerificationError:
        results["issues"].append("SSL certificate verification failed")
        print("[-] SSL verification failed")
    except Exception as e:
        results["issues"].append(f"SSL check failed: {str(e)}")
        print(f"[-] SSL check error: {e}")

    return results

# ── Have I Been Pwned ─────────────────────────────────────────────────────────

def check_hibp(domain, api_key=None):
    print(f"[*] Checking Have I Been Pwned for {domain}...")

    if not api_key:
        print("[!] No HIBP API key configured, skipping")
        return {"breached": False, "breach_count": 0, "breaches": [], "status": "not_configured"}

    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
            headers={
                "User-Agent": "VendorRiskPlatform/1.0",
                "hibp-api-key": api_key
            },
            timeout=10
        )
        if r.status_code == 200:
            breaches = r.json()
            print(f"[+] Found {len(breaches)} breach(es)")
            return {"breached": True, "breach_count": len(breaches), "breaches": breaches, "status": "ok"}
        elif r.status_code == 404:
            print("[+] No breaches found")
            return {"breached": False, "breach_count": 0, "breaches": [], "status": "ok"}
        elif r.status_code == 401:
            print("[!] HIBP API key invalid")
            return {"breached": False, "breach_count": 0, "breaches": [], "status": "invalid_key"}
        else:
            print(f"[-] HIBP returned status {r.status_code}")
            return {"breached": False, "breach_count": 0, "breaches": [], "status": "unavailable"}
    except Exception as e:
        print(f"[-] HIBP check failed: {e}")
        return {"breached": False, "breach_count": 0, "breaches": [], "status": "unavailable"}

# ── NIST NVD CVE lookup ───────────────────────────────────────────────────────

def check_nvd(keyword):
    print(f"[*] Searching NIST NVD for CVEs related to '{keyword}'...")
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": 5},
            timeout=15
        )
        data = r.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc = cve.get("descriptions", [{}])[0].get("value", "")
            metrics = cve.get("metrics", {})
            score = None
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            cves.append({
                "id": cve_id,
                "description": desc[:200],
                "score": score,
                "note": "Keyword-based match — manual verification recommended"
            })

        print(f"[+] Found {len(cves)} CVEs (keyword-based)")
        return cves
    except Exception as e:
        print(f"[-] NVD lookup failed: {e}")
        return []

# ── Shodan ────────────────────────────────────────────────────────────────────

def check_shodan(domain, api_key):
    if not api_key:
        print("[!] No Shodan API key provided, skipping")
        return {"open_ports": [], "vulns": [], "services": [], "error": "No API key"}

    print(f"[*] Querying Shodan for {domain}...")
    try:
        import shodan

        # Resolve domain to IP first (free tier requires IP lookup)
        ip = socket.gethostbyname(domain)
        print(f"[*] Resolved {domain} to {ip}")

        api = shodan.Shodan(api_key)
        host = api.host(ip)

        findings = {"open_ports": [], "vulns": [], "services": []}

        for item in host.get("data", []):
            port = item.get("port")
            if port and port not in findings["open_ports"]:
                findings["open_ports"].append(port)
            product = item.get("product", "")
            if product and product not in findings["services"]:
                findings["services"].append(product)

        for vuln in host.get("vulns", {}).keys():
            findings["vulns"].append(vuln)

        print(f"[+] Shodan: {len(findings['open_ports'])} ports, {len(findings['vulns'])} vulns")
        return findings

    except Exception as e:
        print(f"[-] Shodan failed: {e}")
        return {"open_ports": [], "vulns": [], "services": [], "error": str(e)}

# ── VirusTotal ────────────────────────────────────────────────────────────────

def check_virustotal(domain, api_key):
    if not api_key:
        print("[!] No VirusTotal API key provided, skipping")
        return {"malicious": 0, "suspicious": 0, "error": "No API key"}

    print(f"[*] Querying VirusTotal for {domain}...")
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=15
        )
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        result = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }
        print(f"[+] VirusTotal: {result['malicious']} malicious, {result['suspicious']} suspicious")
        return result
    except Exception as e:
        print(f"[-] VirusTotal failed: {e}")
        return {"malicious": 0, "suspicious": 0, "error": str(e)}

# ── Master scan function ──────────────────────────────────────────────────────

def run_scan(domain, shodan_key=None, vt_key=None, hibp_key=None):
    print(f"\n{'='*50}")
    print(f"  Starting scan: {domain}")
    print(f"{'='*50}\n")

    subdomain_result = get_subdomains(domain)
    dns_result       = check_dns(domain)
    ssl_result       = check_ssl(domain)
    hibp_result      = check_hibp(domain, hibp_key)
    nvd_result       = check_nvd(domain.split(".")[0])
    shodan_result    = check_shodan(domain, shodan_key)
    vt_result        = check_virustotal(domain, vt_key)

    # Calculate data completeness
    sources = {
        "crt.sh":     subdomain_result.get("status") == "ok",
        "DNS/SSL":    True,  # always runs
        "HIBP":       hibp_result.get("status") == "ok",
        "Shodan":     "error" not in shodan_result or shodan_result.get("error") != "No API key",
        "VirusTotal": "error" not in vt_result or vt_result.get("error") != "No API key",
    }
    active   = sum(sources.values())
    total    = len(sources)
    coverage = round((active / total) * 100)

    if coverage >= 80:
        confidence = "High"
    elif coverage >= 50:
        confidence = "Medium"
    else:
        confidence = "Low"

    print(f"\n[*] Scan coverage: {active}/{total} sources active ({confidence} confidence)")

    findings = {
        "domain":      domain,
        "scanned_at":  datetime.now(timezone.utc).isoformat(),
        "subdomains":  subdomain_result,
        "dns":         dns_result,
        "ssl":         ssl_result,
        "hibp":        hibp_result,
        "nvd":         nvd_result,
        "shodan":      shodan_result,
        "virustotal":  vt_result,
        "coverage": {
            "sources":    sources,
            "active":     active,
            "total":      total,
            "percent":    coverage,
            "confidence": confidence,
        }
    }

    print(f"[✓] Scan complete for {domain}")
    return findings


if __name__ == "__main__":
    import sys
    import os
    domain = sys.argv[1] if len(sys.argv) > 1 else "github.com"
    results = run_scan(
        domain,
        shodan_key=os.environ.get("SHODAN_API_KEY"),
        vt_key=os.environ.get("VT_API_KEY"),
        hibp_key=os.environ.get("HIBP_API_KEY")
    )
    print(json.dumps(results, indent=2))
