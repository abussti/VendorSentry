# app.py
from report import generate_vendor_report
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
from models import init_db, save_vendor, save_assessment, get_all_vendors, get_vendor_history, get_db
from scanner import run_scan
from scorer import run_scoring
from llm import generate_summary
import json
import os
from datetime import datetime

app = Flask(__name__)
import json as _json
app.jinja_env.filters['from_json'] = _json.loads
BRAND_DISPLAY = {
    "paypal": "PayPal", "microsoft": "Microsoft",
    "google": "Google", "apple": "Apple",
    "amazon": "Amazon", "netflix": "Netflix",
    "facebook": "Facebook", "linkedin": "LinkedIn",
    "dhl": "DHL", "fedex": "FedEx", "ups": "UPS",
    "hsbc": "HSBC", "barclays": "Barclays",
    "emirates": "Emirates", "etisalat": "Etisalat"
}

def brand_name_filter(brands):
    if isinstance(brands, list):
        return ", ".join(BRAND_DISPLAY.get(b, b.title()) for b in brands)
    return BRAND_DISPLAY.get(brands, brands.title())

app.jinja_env.filters['brand_name'] = brand_name_filter
# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    vendors = get_all_vendors()
    vendors = [dict(v) for v in vendors]

    total_vendors  = len(vendors)
    high_risk      = sum(1 for v in vendors if v.get("risk_level") == "High")
    avg_score      = round(sum(v["latest_score"] for v in vendors if v["latest_score"]) / total_vendors, 1) if total_vendors else 0
    alerts         = sum(1 for v in vendors if v.get("alert_triggered"))

    return render_template("dashboard.html",
        vendors=vendors,
        total_vendors=total_vendors,
        high_risk=high_risk,
        avg_score=avg_score,
        alerts=alerts
    )

# ── Add and scan a vendor ─────────────────────────────────────────────────────

@app.route("/scan", methods=["POST"])
def scan():
    name   = request.form.get("name", "").strip()
    domain = request.form.get("domain", "").strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

    if not name or not domain:
        return jsonify({"error": "Name and domain are required"}), 400

    # Run full scan pipeline
    findings = run_scan(domain,
        shodan_key=os.environ.get("SHODAN_API_KEY"),
        vt_key=os.environ.get("VT_API_KEY"),
        hibp_key=os.environ.get("HIBP_API_KEY")
    )

    scores = run_scoring(findings)
    ai_summary = generate_summary(domain, scores, findings)

    # Save to database
    vendor_id = save_vendor(name, domain)

    # Check if score has worsened by more than 10 points vs last scan
    conn = get_db()
    last = conn.execute(
        "SELECT score FROM assessments WHERE vendor_id = ? ORDER BY scanned_at DESC LIMIT 1",
        (vendor_id,)
    ).fetchone()
    conn.close()

    alert = False
    if last and last["score"] and (last["score"] - scores["total"]) > 10:
        alert = True
        conn = get_db()
        conn.execute("UPDATE vendors SET alert_triggered = 1 WHERE id = ?", (vendor_id,))
        conn.commit()
        conn.close()

    save_assessment(vendor_id, scores, ai_summary, findings)

    # Generate PDF report
    try:
        report_path = generate_vendor_report(
            vendor={"name": name, "domain": domain,
                    "risk_level": scores["risk_level"],
                    "last_scanned": datetime.utcnow().strftime("%Y-%m-%d")},
            assessment={"ai_summary": ai_summary},
            findings=findings,
            scores=scores
        )
        # Save report path to latest assessment
        conn = get_db()
        latest = conn.execute(
            "SELECT id FROM assessments WHERE vendor_id = ? ORDER BY scanned_at DESC LIMIT 1",
            (vendor_id,)
        ).fetchone()
        if latest:
            conn.execute(
                "UPDATE assessments SET report_path = ? WHERE id = ?",
                (report_path, latest["id"])
            )
            conn.commit()
        conn.close()
    except Exception as e:
        print(f"[-] PDF generation failed: {e}")

    return redirect(url_for("vendor_detail", vendor_id=vendor_id))

# ── Vendor detail page ────────────────────────────────────────────────────────

@app.route("/vendor/<int:vendor_id>")
def vendor_detail(vendor_id):
    conn = get_db()
    vendor = conn.execute(
        "SELECT * FROM vendors WHERE id = ?", (vendor_id,)
    ).fetchone()

    assessments = conn.execute(
        "SELECT * FROM assessments WHERE vendor_id = ? ORDER BY scanned_at DESC",
        (vendor_id,)
    ).fetchall()
    conn.close()

    if not vendor:
        return "Vendor not found", 404

    vendor = dict(vendor)
    assessments = [dict(a) for a in assessments]

    # Parse raw findings for latest assessment
    latest_findings = {}
    if assessments and assessments[0].get("raw_findings"):
        latest_findings = json.loads(assessments[0]["raw_findings"])

    # Build score history for Chart.js trend chart
    score_history = [
        {"date": a["scanned_at"][:10], "score": a["score"]}
        for a in assessments
    ]

    return render_template("vendor.html",
        vendor=vendor,
        assessments=assessments,
        latest_findings=latest_findings,
        score_history=score_history,
        latest=assessments[0] if assessments else None
    )

# ── Download PDF report ───────────────────────────────────────────────────────

@app.route("/report/<int:assessment_id>")
def download_report(assessment_id):
    conn = get_db()
    assessment = conn.execute(
        "SELECT * FROM assessments WHERE id = ?", (assessment_id,)
    ).fetchone()
    conn.close()

    if not assessment or not assessment["report_path"]:
        return "Report not found", 404

    return send_file(assessment["report_path"], as_attachment=True)

# ── Download email PDF report ─────────────────────────────────────────────────
@app.route("/email/report/<int:analysis_id>")
def download_email_report(analysis_id):
    from report import generate_email_report

    conn = get_db()
    analysis = conn.execute(
        "SELECT * FROM email_analyses WHERE id = ?", (analysis_id,)
    ).fetchone()
    conn.close()

    if not analysis:
        return "Analysis not found", 404

    analysis = dict(analysis)

    # Deserialise JSON fields
    for field in ["impersonation_hits", "risk_factors", "threat_intel",
                  "urls_found", "keyword_hits", "header_issues"]:
        if analysis.get(field):
            try:
                analysis[field] = json.loads(analysis[field])
            except Exception:
                analysis[field] = []

    # Rebuild content_analysis structure
    analysis["content_analysis"] = {
        "keyword_hits": analysis.get("keyword_hits", []),
        "pattern_flags": {}
    }

    # Rebuild domain age
    analysis["domain_age"] = {
        "age_days": analysis.get("domain_age_days"),
        "label":    analysis.get("domain_age_label", "Unknown")
    }

    report_path = generate_email_report(analysis)
    return send_file(report_path, as_attachment=True)



# ── API endpoint for live scan status ────────────────────────────────────────

@app.route("/api/vendors")
def api_vendors():
    vendors = get_all_vendors()
    return jsonify([dict(v) for v in vendors])

@app.route("/email")
def email_analyzer_page():
    conn = get_db()
    analyses = conn.execute(
        "SELECT * FROM email_analyses ORDER BY analyzed_at DESC"
    ).fetchall()
    conn.close()
    return render_template("email.html", analyses=[dict(a) for a in analyses])

@app.route("/email/analyze", methods=["POST"])
def analyze_email_route():
    sender  = request.form.get("sender", "").strip()
    subject = request.form.get("subject", "").strip()
    body    = request.form.get("body", "").strip()
    raw_headers = request.form.get("raw_headers", "").strip() or None

    from email_analyzer import analyze_email
    result = analyze_email(
        sender=sender,
        subject=subject,
        body=body,
        raw_headers=raw_headers,
        vt_key=os.environ.get("VT_API_KEY"),
        shodan_key=os.environ.get("SHODAN_API_KEY"),
        hibp_key=os.environ.get("HIBP_API_KEY")
    )

    conn = get_db()
    conn.execute("""
        INSERT INTO email_analyses
        (sender, sender_domain, subject, email_threat_score, email_risk_level,
         final_score, final_risk_level, confidence, impersonation_hits,
         risk_factors, safe_action, keyword_hits, urls_found,
         sender_domain_score, sender_domain_risk, ai_summary, raw_findings,
         verdict, verdict_level, attack_type, verdict_reason, threat_intel,
         domain_age_days, domain_age_label,
         header_spf, header_dkim, header_dmarc, header_issues, top_drivers)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        result["sender"], result["sender_domain"], result["subject"],
        result["email_threat_score"], result["email_risk_level"],
        result["final_score"], result["final_risk_level"],
        result["confidence"],
        json.dumps(result["impersonation_hits"]),
        json.dumps(result["risk_factors"]),
        result["safe_action"],
        json.dumps(result["content_analysis"]["keyword_hits"]),
        json.dumps(result["urls_found"]),
        result["sender_domain_score"], result["sender_domain_risk"],
        result["ai_summary"],
        json.dumps(result["sender_domain_findings"]),
        result["verdict"],
        result["verdict_level"],
        result["attack_type"],
        result["verdict_reason"],
        json.dumps(result["threat_intel"]),
        result.get("domain_age", {}).get("age_days"),
        result.get("domain_age", {}).get("label"),
        result.get("header_analysis", {}).get("spf", {}).get("label"),
        result.get("header_analysis", {}).get("dkim", {}).get("label"),
        result.get("header_analysis", {}).get("dmarc", {}).get("label"),
        json.dumps(result.get("header_analysis", {}).get("issues", [])),
        json.dumps(result.get("top_drivers", []))
    ))
    conn.commit()
    conn.close()

    return redirect(url_for("email_analyzer_page"))


if __name__ == "__main__":
    init_db()
    print("\n" + "="*50)
    print("  VendorSentry — Supply Chain & Email Threat Intelligence")
    print("  Running at http://localhost:5000")
    print("="*50 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
