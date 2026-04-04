# VendorSentry
### Supply Chain & Email Threat Intelligence Platform

> A proof-of-concept security intelligence platform that automates vendor risk assessment and email phishing analysis — directly addressing the supply chain security gaps identified in Kaspersky's 2026 UAE Cybersecurity Report.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-3.x-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Overview

VendorSentry is a locally-hosted threat intelligence platform combining two core capabilities:

**Vendor Risk Assessment** — automated supply chain security scoring using real threat intelligence sources, aligned to NIST SP 800-161 and ISO 27036.

**Email Threat Analysis** — phishing detection engine with brand impersonation detection, sender domain intelligence, and multi-source risk correlation.

Both modules feed into a unified dashboard with PDF report generation and AI-assisted executive summaries powered by a locally-hosted LLM (Ollama / phi3:mini) — ensuring data never leaves your environment.

---

## Screenshots

<!-- SCREENSHOT 1: Dashboard overview showing vendor list with risk badges -->
![Dashboard](screenshots/dashboard.png)
*Vendor risk dashboard with colour-coded risk levels and summary statistics*

<!-- SCREENSHOT 2: Vendor detail page showing score breakdown bars and AI summary -->
![Vendor Detail](screenshots/vendor_detail.png)
*Vendor detail page with per-category score breakdown and AI executive summary*

<!-- SCREENSHOT 3: Email analyzer page showing the phishing result expanded -->
![Email Analyzer](screenshots/email_analyzer.png)
*Email threat analysis showing verdict, threat intelligence summary, and top risk drivers*

<!-- SCREENSHOT 4: PDF report - first page showing verdict box and score cards -->
![PDF Report](screenshots/pdf_report.png)
*Generated PDF report suitable for management or compliance purposes*

---

## Features

### Vendor Risk Assessment
- Subdomain discovery via crt.sh certificate transparency logs
- DNS and email security checks (SPF, DMARC, MX records)
- SSL/TLS certificate validity and expiry monitoring
- Open port and exposed service discovery via Shodan
- Domain reputation scoring via VirusTotal (63+ engines)
- Breach history lookup via Have I Been Pwned
- CVE lookup via NIST NVD (keyword-based, with disclaimer)
- Data completeness scoring — confidence rating based on active sources
- Risk trend tracking with re-scan history and alert triggering

### Email Threat Analysis
- Brand impersonation detection (PayPal, Microsoft, Google, Apple, and 14 others)
- Phishing keyword detection with pattern analysis
- URL extraction and VirusTotal reputation checking
- Full vendor risk scan on sender domain
- Email header authentication analysis (SPF, DKIM, DMARC pass/fail)
- Domain age lookup via WHOIS
- Attack type classification (Credential Harvesting, Malware Delivery, Financial Scam, etc.)
- Combined email + domain risk scoring with confidence rating
- Verdict generation with multi-source reasoning

### Intelligence & Reporting
- AI executive summaries via locally-hosted Ollama (phi3:mini) — no data leaves the machine
- Professional PDF reports for both vendor assessments and email analyses
- Risk trend charts via Chart.js
- Score drop alerting (configurable threshold)
- CLI batch mode and JSON output for integration

---

## Risk Scoring Framework

Vendor risk is scored 0–100 using a weighted framework aligned to NIST SP 800-161:

| Category | Weight | Signals |
|---|---|---|
| Breach History | 25% | HIBP hits, VirusTotal malicious flags |
| Exposed Services | 25% | Open ports (RDP, SMB, Redis, etc.), Shodan findings |
| Vulnerability Exposure | 20% | CVEs on detected technologies |
| DNS / Email Security | 15% | Missing SPF, DMARC, DKIM |
| SSL / TLS Health | 15% | Expired certs, invalid certificates |

**Risk thresholds:**
- 🔴 **High Risk (0–39)** — Do not engage without remediation
- 🟡 **Medium Risk (40–69)** — Engage with conditions and monitoring
- 🟢 **Low Risk (70–100)** — Acceptable risk profile

---

## Tech Stack

| Component | Technology |
|---|---|
| Backend | Python 3.10+ / Flask |
| Database | SQLite |
| PDF Generation | fpdf2 |
| AI Summary | Ollama + phi3:mini (local) |
| Frontend | Flask + Chart.js |
| DNS Checks | dnspython |
| SSL Checks | Python ssl + socket |
| External APIs | Shodan, VirusTotal, HIBP, NIST NVD, crt.sh |

---

## Installation

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.com) installed and running

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/VendorSentry.git
cd VendorSentry

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Pull the AI model
ollama pull phi3:mini

# Configure API keys
cp .env.example .env
# Edit .env and add your API keys

# Initialise the database
python3 models.py

# Run the application
python3 app.py
```

Open your browser at `http://localhost:5000`

---

## API Keys

| Service | Required | Free Tier | Link |
|---|---|---|---|
| Shodan | Recommended | 100 queries/month | [shodan.io](https://shodan.io) |
| VirusTotal | Recommended | 500 requests/day | [virustotal.com](https://virustotal.com) |
| Have I Been Pwned | Optional | Paid subscription | [haveibeenpwned.com](https://haveibeenpwned.com) |
| NIST NVD | Not required | Public API | Automatic |
| crt.sh | Not required | Public API | Automatic |

Create a `.env` file in the project root:

```env
SHODAN_API_KEY=your_key_here
VT_API_KEY=your_key_here
HIBP_API_KEY=your_key_here
```

> The platform runs with partial data if some keys are missing. A confidence score indicates how many sources were active during each scan.

---

## Usage

### Vendor Assessment

1. Navigate to the dashboard at `http://localhost:5000`
2. Enter a vendor name and domain (e.g. `Acme Corp` / `acmecorp.com`)
3. Click **Run Assessment** — the scan takes 3–5 minutes
4. View the risk score, findings, and AI summary on the vendor detail page
5. Download the PDF report for management or compliance use

Re-scanning a vendor automatically compares scores and triggers an alert if risk increases by more than 10 points.

### Email Analysis

1. Navigate to `http://localhost:5000/email`
2. Paste the sender address, subject line, and email body
3. Optionally paste the `Authentication-Results` header block for SPF/DKIM/DMARC analysis
4. Click **Analyze Email** — takes 3–5 minutes due to domain scan and AI summary
5. View the verdict, risk drivers, threat intelligence summary, and recommended actions

Use **Load Demo Phishing Email** to test with a pre-built example.

### CLI Mode

```bash
# Single email analysis
python3 email_analyzer.py --sender "support@suspicious.com" --subject "Urgent" --body "..."

# JSON output for integration
python3 email_analyzer.py --json

# Batch analysis from file
python3 email_analyzer.py emails.json
```

---

## Project Structure

```
VendorSentry/
├── app.py              # Flask application and routes
├── scanner.py          # Threat intelligence gathering
├── scorer.py           # NIST-aligned risk scoring engine
├── email_analyzer.py   # Email phishing analysis engine
├── report.py           # PDF report generation
├── llm.py              # Ollama AI summary integration
├── models.py           # SQLite database models
├── templates/
│   ├── dashboard.html  # Vendor risk dashboard
│   ├── vendor.html     # Vendor detail page
│   └── email.html      # Email analyzer page
├── static/             # CSS, JS assets
├── reports/            # Generated PDF reports
├── .env.example        # API key template
├── requirements.txt
└── README.md
```

---

## Context

Built as a portfolio project demonstrating practical supply chain security skills relevant to SOC analyst and blue team roles in the UAE. The platform mirrors commercial tools like SecurityScorecard and BitSight at proof-of-concept level, and directly addresses the tooling and talent gaps identified in Kaspersky's March 2026 UAE Cybersecurity Report.

The AI summary feature uses Ollama running locally — all data stays on-premise, which is particularly relevant in the UAE context where data sovereignty is a regulatory concern.

---

## Limitations & Disclaimers

- CVE results are keyword-based and require manual verification to confirm relevance
- NVD lookups use domain keywords and may return unrelated vulnerabilities
- Free tier API keys have rate limits that may affect scan completeness
- AI summaries are generated by a small local model and should be reviewed before use in formal reports
- This is a proof-of-concept tool and has not been security-hardened for production deployment

---

## License

MIT License — see [LICENSE](LICENSE) for details.
