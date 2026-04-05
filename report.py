# report.py

import os
from datetime import datetime
from fpdf import FPDF

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── Colour palette (dark theme) ───────────────────────────────────────────────
BG       = (15,  17,  23)
CARD     = (26,  29,  39)
BORDER   = (45,  49,  72)
TEXT     = (226, 232, 240)
MUTED    = (100, 116, 139)
PURPLE   = (167, 139, 250)
RED      = (248, 113, 113)
AMBER    = (251, 191,  36)
GREEN    = ( 52, 211, 153)
RED_BG   = ( 63,  23,  23)
AMBER_BG = ( 63,  46,   0)
GREEN_BG = (  5,  46,  22)

# ── Helpers ───────────────────────────────────────────────────────────────────

def c(text):
    """Sanitise text for fpdf2 core fonts (Latin-1 only)."""
    if not text:
        return ""
    text = str(text)
    for bad, good in [
        ("\u2014", "-"), ("\u2013", "-"), ("\u2018", "'"), ("\u2019", "'"),
        ("\u201c", '"'), ("\u201d", '"'), ("--", "-"),
        ("-", "-"),  # regular hyphen passthrough
    ]:
        text = text.replace(bad, good)
    # Strip any remaining non-latin-1 characters
    return text.encode("latin-1", errors="replace").decode("latin-1")

def clean_ai(text):
    """Truncate AI output at hallucination triggers and cap length."""
    text = c(text)
    for trigger in ["Your task:", "Task:", "Exercise:", "As the head", "---", "Note:"]:
        if trigger in text:
            text = text[:text.index(trigger)].strip()
    if len(text) > 700:
        text = text[:700]
        for punct in [". ", "! ", "? "]:
            idx = text.rfind(punct)
            if idx > 300:
                text = text[:idx + 1].strip()
                break
    return text

def risk_colour(level):
    return RED if level == "High" else AMBER if level in ("Medium", "Medium-High") else GREEN

def risk_bg(level):
    return RED_BG if level == "High" else AMBER_BG if level in ("Medium", "Medium-High") else GREEN_BG

def score_colour(score):
    try:
        s = int(str(score).split("/")[0])
        return RED if s < 40 else AMBER if s < 70 else GREEN
    except Exception:
        return TEXT

# ── Base PDF ──────────────────────────────────────────────────────────────────

class RiskReport(FPDF):

    def add_page(self, *args, **kwargs):
        super().add_page(*args, **kwargs)
        # Draw dark background immediately after page creation
        self.set_fill_color(*BG)
        self.rect(0, 0, 210, 297, "F")

    def header(self):
        # Navy top bar
        self.set_fill_color(*CARD)
        self.rect(0, 0, 210, 16, "F")
        self.set_xy(0, 3)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*PURPLE)
        self.cell(0, 8, "  VENDORSENTRY  |  Supply Chain & Email Threat Intelligence", align="L")
        self.set_xy(0, 3)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 8, "CONFIDENTIAL  ", align="R")
        self.ln(14)

    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*MUTED)
        self.cell(0, 8,
            f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC  |  Page {self.page_no()}",
            align="C")

    # ── Drawing helpers ───────────────────────────────────────────────────────

    def section_title(self, text):
        self.ln(5)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*MUTED)
        self.set_x(20)
        self.cell(0, 5, c(text).upper(), ln=True)
        self.set_draw_color(*BORDER)
        self.set_line_width(0.3)
        self.line(20, self.get_y(), 190, self.get_y())
        self.ln(4)

    def score_box(self, x, y, w, label, value, colour):
        self.set_fill_color(*CARD)
        self.set_draw_color(*BORDER)
        self.set_line_width(0.3)
        self.rect(x, y, w, 26, "FD")
        self.set_xy(x, y + 3)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*MUTED)
        self.cell(w, 4, c(label).upper(), align="C")
        self.set_xy(x, y + 8)
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(*colour)
        self.cell(w, 10, c(str(value)), align="C")

    def verdict_box(self, text, level):
        col = risk_colour(level)
        bg  = risk_bg(level)
        self.set_fill_color(*bg)
        self.set_draw_color(*col)
        self.set_line_width(0.6)
        y = self.get_y()
        self.rect(20, y, 170, 11, "FD")
        self.set_xy(21, y + 2)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*col)
        self.cell(168, 7, c(text), align="L")
        self.ln(15)

    def info_row(self, label, value, colour=None):
        self.set_x(20)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(52, 6, c(label))
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*(colour or TEXT))
        self.multi_cell(0, 6, c(str(value)))

    def bullet(self, text, colour=None):
        self.set_x(20)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*(colour or TEXT))
        self.multi_cell(0, 5, c("- " + str(text)))
        self.ln(1)

    def body_text(self, text, size=8):
        self.set_x(20)
        self.set_font("Helvetica", "", size)
        self.set_text_color(*TEXT)
        self.multi_cell(0, 5, clean_ai(str(text)))
        self.ln(2)

    def bar(self, label, score, w=170):
        bar_w  = w - 46
        filled = max(0, min(int((score / 100) * bar_w), bar_w))
        col    = score_colour(score)
        self.set_x(20)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*TEXT)
        self.cell(42, 5, c(label))
        y = self.get_y()
        self.set_fill_color(*BORDER)
        self.rect(62, y + 1, bar_w, 3, "F")
        if filled > 0:
            self.set_fill_color(*col)
            self.rect(62, y + 1, filled, 3, "F")
        self.set_x(62 + bar_w + 2)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*col)
        self.cell(10, 5, str(score), align="R")
        self.ln(7)


# ── Vendor report ─────────────────────────────────────────────────────────────

def generate_vendor_report(vendor, assessment, findings, scores):
    pdf = RiskReport()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(20, 20, 20)
    pdf.add_page()

    domain     = vendor.get("domain", "unknown")
    name       = vendor.get("name", domain)
    risk_level = vendor.get("risk_level", "Unknown")
    total      = scores.get("total", 0)
    confidence = scores.get("confidence", "Unknown")
    coverage   = scores.get("coverage", "")
    scanned    = (vendor.get("last_scanned") or "")[:10] or "Unknown"
    ai_summary = assessment.get("ai_summary", "No summary available.")
    dns        = findings.get("dns", {})
    ssl        = findings.get("ssl", {})

    # Title
    pdf.set_x(20)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(*TEXT)
    pdf.cell(0, 10, "Vendor Risk Assessment", ln=True)
    pdf.set_x(20)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 6, c(f"{name}  |  {domain}  |  Scanned {scanned}"), ln=True)
    pdf.ln(4)

    # Verdict
    pdf.verdict_box(f"RISK VERDICT: {risk_level} Risk  |  Score: {total}/100", risk_level)

    # Score boxes
    y = pdf.get_y()
    pdf.score_box(20,  y, 52, "Overall Score",   f"{total}/100",               score_colour(total))
    pdf.score_box(76,  y, 52, "Breach / Rep",    f"{scores.get('breach',0)}/100", score_colour(scores.get('breach',0)))
    pdf.score_box(132, y, 58, "Data Confidence", str(confidence),               PURPLE)
    pdf.ln(32)

    # Score bars
    pdf.section_title("Score Breakdown")
    pdf.bar("Breach History",   scores.get("breach",   0))
    pdf.bar("Exposed Services", scores.get("exposure", 0))
    pdf.bar("Vulnerability",    scores.get("vuln",     0))
    pdf.bar("DNS / Email Sec",  scores.get("dns",      0))
    pdf.bar("SSL / TLS",        scores.get("ssl",      0))

    # Vendor details
    pdf.section_title("Vendor Details")
    pdf.info_row("Domain",       domain)
    pdf.info_row("Risk Level",   risk_level,                                        risk_colour(risk_level))
    pdf.info_row("SPF Record",   "Configured" if dns.get("has_spf")   else "MISSING", GREEN if dns.get("has_spf")   else RED)
    pdf.info_row("DMARC Record", "Configured" if dns.get("has_dmarc") else "MISSING", GREEN if dns.get("has_dmarc") else RED)
    pdf.info_row("SSL Valid",    "Yes"        if ssl.get("valid")     else "NO",      GREEN if ssl.get("valid")     else RED)
    pdf.info_row("SSL Days",     f"{ssl.get('days_remaining', 'N/A')} days")
    pdf.info_row("Coverage",     coverage)

    # CVEs
    nvd = findings.get("nvd", [])
    if nvd:
        pdf.section_title(f"CVE Findings ({len(nvd)} keyword-based matches)")
        for cve in nvd:
            s = cve.get("score", 0)
            col = RED if isinstance(s, float) and s >= 7 else AMBER if isinstance(s, float) and s >= 4 else GREEN
            pdf.set_x(20)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*col)
            pdf.cell(40, 5, c(cve.get("id", "")))
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(*MUTED)
            pdf.cell(0, 5, f"CVSS {s}", ln=True)
            pdf.set_x(20)
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(*TEXT)
            pdf.multi_cell(0, 4, c(cve.get("description", "")[:130] + "..."))
            pdf.ln(1)

    # DNS issues
    issues = dns.get("issues", [])
    if issues:
        pdf.section_title("DNS / Email Security Issues")
        for issue in issues:
            pdf.bullet(issue, AMBER)

    # Open ports
    ports = findings.get("shodan", {}).get("open_ports", [])
    if ports:
        pdf.section_title("Exposed Services (Shodan)")
        pdf.info_row("Open Ports", ", ".join(str(p) for p in ports))

    # AI summary
    pdf.section_title("Executive Summary (AI-Assisted)")
    pdf.set_fill_color(30, 27, 75)
    pdf.set_draw_color(67, 56, 202)
    ai_y = pdf.get_y()
    pdf.rect(20, ai_y, 170, 6, "F")
    pdf.set_xy(21, ai_y + 1)
    pdf.set_font("Helvetica", "B", 6)
    pdf.set_text_color(165, 180, 252)
    pdf.cell(168, 4, "AI GENERATED  |  phi3:mini via Ollama", ln=True)
    pdf.ln(3)
    pdf.body_text(ai_summary, size=9)

    # Subdomains
    sub_data = findings.get("subdomains", {})
    subs = sub_data.get("subdomains", []) if isinstance(sub_data, dict) else (sub_data or [])
    if subs:
        pdf.section_title(f"Discovered Subdomains ({len(subs)})")
        pdf.set_font("Courier", "", 7)
        pdf.set_text_color(*MUTED)
        for i, sub in enumerate(subs[:60]):
            col_idx = i % 3
            if col_idx == 0:
                pdf.set_x(20)
            pdf.cell(56, 5, c(sub[:32]))
            if col_idx == 2:
                pdf.ln()
        pdf.ln(6)

    # Metadata
    pdf.section_title("Assessment Metadata")
    pdf.info_row("Generated",  datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    pdf.info_row("Platform",   "VendorSentry v1.0")
    pdf.info_row("Framework",  "NIST SP 800-161 / ISO 27036")
    pdf.info_row("Sources",    "Shodan, VirusTotal, HIBP, NIST NVD, crt.sh, DNS, SSL")

    filename = f"{REPORTS_DIR}/vendor_{c(domain)}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(filename)
    print(f"[+] Vendor report saved: {filename}")
    return filename


# ── Email report ──────────────────────────────────────────────────────────────

def generate_email_report(analysis):
    pdf = RiskReport()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(20, 20, 20)
    pdf.add_page()

    sender        = analysis.get("sender", "unknown")
    subject       = analysis.get("subject", "")
    email_threat  = int(analysis.get("email_threat_score") or 0)
    final_score   = int(analysis.get("final_score") or 0)
    email_risk    = analysis.get("email_risk_level", "Unknown")
    final_risk    = analysis.get("final_risk_level", "Unknown")
    confidence    = analysis.get("confidence", 0)
    verdict       = analysis.get("verdict", "Unknown")
    verdict_level = analysis.get("verdict_level", "High")
    attack_type   = analysis.get("attack_type", "Unknown")
    impersonation = analysis.get("impersonation_hits") or []
    if isinstance(impersonation, str):
        import json
        try: impersonation = json.loads(impersonation)
        except: impersonation = []
    top_drivers   = analysis.get("top_drivers") or []
    if isinstance(top_drivers, str):
        import json
        try: top_drivers = json.loads(top_drivers)
        except: top_drivers = []
    threat_intel  = analysis.get("threat_intel") or []
    if isinstance(threat_intel, str):
        import json
        try: threat_intel = json.loads(threat_intel)
        except: threat_intel = []
    risk_factors  = analysis.get("risk_factors") or []
    if isinstance(risk_factors, str):
        import json
        try: risk_factors = json.loads(risk_factors)
        except: risk_factors = []
    keywords      = (analysis.get("content_analysis") or {}).get("keyword_hits") or []
    if isinstance(keywords, str):
        import json
        try: keywords = json.loads(keywords)
        except: keywords = []
    urls          = analysis.get("urls_found") or []
    if isinstance(urls, str):
        import json
        try: urls = json.loads(urls)
        except: urls = []
    safe_action   = analysis.get("safe_action", "")
    ai_summary    = analysis.get("ai_summary", "No summary available.")
    domain_age    = analysis.get("domain_age_label", "")

    try:
        from email_analyzer import BRAND_DISPLAY
    except Exception:
        BRAND_DISPLAY = {}

    # Title
    pdf.set_x(20)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(*TEXT)
    pdf.cell(0, 10, "Email Threat Assessment", ln=True)
    pdf.set_x(20)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 5, c(f"From: {sender}  |  Analyzed: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"), ln=True)
    pdf.ln(4)

    # Verdict
    pdf.verdict_box(f"VERDICT: {verdict}", verdict_level)

    # Score boxes
    y = pdf.get_y()
    pdf.score_box(20,  y, 52, "Email Threat", f"{email_threat}/100", score_colour(email_threat))
    pdf.score_box(76,  y, 52, "Final Risk",   f"{final_score}/100",  score_colour(final_score))
    pdf.score_box(132, y, 58, "Confidence",   f"{confidence}%",      PURPLE)
    pdf.ln(32)

    # Brand impersonation banner
    if impersonation:
        brand_name = BRAND_DISPLAY.get(impersonation[0], impersonation[0].title())
        col = risk_colour("High")
        bg  = risk_bg("High")
        pdf.set_fill_color(*bg)
        pdf.set_draw_color(*col)
        pdf.set_line_width(0.5)
        imp_y = pdf.get_y()
        pdf.rect(20, imp_y, 170, 10, "FD")
        pdf.set_xy(21, imp_y + 2)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*col)
        pdf.cell(168, 6, c(f"BRAND IMPERSONATION DETECTED - domain mimics '{brand_name}'"), align="L")
        pdf.ln(14)

    # Attack type
    pdf.set_x(20)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*MUTED)
    pdf.cell(40, 6, "Attack Classification:")
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*PURPLE)
    pdf.cell(0, 6, c(attack_type), ln=True)
    pdf.ln(2)

    # Top risk drivers
    if top_drivers:
        pdf.section_title("Top Risk Drivers")
        for i, driver in enumerate(top_drivers, 1):
            pdf.set_x(20)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*TEXT)
            pdf.multi_cell(0, 5, c(f"{i}. {driver}"))
        pdf.ln(2)

    # Threat intel
    if threat_intel:
        pdf.section_title("Threat Intelligence Summary")
        for item in threat_intel:
            pdf.set_x(20)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*MUTED)
            pdf.cell(6, 5, "-")
            pdf.set_text_color(*TEXT)
            pdf.multi_cell(0, 5, c(str(item)))
        if domain_age:
            pdf.set_x(20)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*MUTED)
            pdf.cell(6, 5, "-")
            pdf.set_text_color(*AMBER)
            pdf.multi_cell(0, 5, c(f"Domain Age: {domain_age}"))
        pdf.ln(2)

    # Email details
    sender_domain_risk = analysis.get("sender_domain_risk", "Unknown")
    sender_domain_score = analysis.get("sender_domain_score", "N/A")
    pdf.section_title("Email Details")
    pdf.info_row("Sender",      sender)
    pdf.info_row("Subject",     subject[:70])
    pdf.info_row("Domain",      analysis.get("sender_domain", ""))
    pdf.info_row("Domain Risk", f"{sender_domain_score}/100 ({sender_domain_risk} Risk)",
                 risk_colour(sender_domain_risk))

    # Risk factors
    if risk_factors:
        pdf.section_title(f"Risk Factors ({len(risk_factors)} Identified)")
        for factor in risk_factors:
            pdf.bullet(factor, AMBER)

    # Keywords
    if keywords:
        pdf.section_title("Phishing Keywords Detected")
        pdf.set_x(20)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*RED)
        pdf.multi_cell(0, 5, c("  |  ".join(keywords)))
        pdf.ln(2)

    # URLs
    if urls:
        pdf.section_title(f"URLs Found ({len(urls)})")
        for url in urls:
            pdf.set_x(20)
            pdf.set_font("Courier", "", 8)
            pdf.set_text_color(*RED)
            pdf.multi_cell(0, 5, c(str(url)))
        pdf.ln(2)

    # Safe action
    if safe_action:
        pdf.set_fill_color(*GREEN_BG)
        pdf.set_draw_color(*GREEN)
        pdf.set_line_width(0.4)
        safe_y = pdf.get_y()
        pdf.rect(20, safe_y, 170, 13, "FD")
        pdf.set_xy(21, safe_y + 2)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*GREEN)
        pdf.multi_cell(168, 5, c(f"SAFE ALTERNATIVE:  {safe_action}"))
        pdf.ln(7)

    # AI summary
    pdf.section_title("Executive Summary (AI-Assisted)")
    pdf.set_fill_color(30, 27, 75)
    pdf.set_draw_color(67, 56, 202)
    ai_y = pdf.get_y()
    pdf.rect(20, ai_y, 170, 6, "F")
    pdf.set_xy(21, ai_y + 1)
    pdf.set_font("Helvetica", "B", 6)
    pdf.set_text_color(165, 180, 252)
    pdf.cell(168, 4, "AI GENERATED  |  phi3:mini via Ollama", ln=True)
    pdf.ln(3)
    pdf.body_text(ai_summary, size=9)

    # Metadata
    pdf.section_title("Assessment Metadata")
    pdf.info_row("Generated",       datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    pdf.info_row("Platform",        "VendorSentry v1.0")
    pdf.info_row("Analysis Engine", "Content Analysis + Domain Intelligence + Local LLM")

    domain_slug = c(analysis.get("sender_domain", "unknown")).replace(".", "_")
    filename = f"{REPORTS_DIR}/email_{domain_slug}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(filename)
    print(f"[+] Email report saved: {filename}")
    return filename
