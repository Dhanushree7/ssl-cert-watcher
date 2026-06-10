# ExpirySense MCP Tools Compilation
import json
import os
import csv
import io
import urllib.request
import urllib.error
from datetime import datetime, timezone
from backend.ssl_scanner import scan_ssl_certificate

def mcp_ssl_scanner_tool(hostname: str) -> dict:
    """
    [MCP SSL Scanner Tool]
    Scans certificate detail live from the given host, and returns structured telemetry.
    """
    return scan_ssl_certificate(hostname)

def mcp_certificate_analyzer_tool(scan_record: dict) -> dict:
    """
    [MCP Certificate Analyzer Tool]
    Examines scanning statuses and assigns threat categorizer assessments.
    """
    status = scan_record.get("status", "UNREACHABLE")
    days = scan_record.get("days_remaining", -1)
    
    analysis = {
        "hostname": scan_record["hostname"],
        "status": status,
        "days_remaining": days,
        "is_threat": status in ["CRITICAL", "WARNING"],
        "summary": ""
    }
    
    if status == "CRITICAL":
        analysis["summary"] = f"Domain {scan_record['hostname']} is in CRITICAL state with only {days} residual days left! Expiration imminent. Immediate rotation required."
    elif status == "WARNING":
        analysis["summary"] = f"Domain {scan_record['hostname']} is approaching expiry with {days} days remaining. Renewal task should be scheduled within the week."
    elif status == "HEALTHY":
        analysis["summary"] = f"Domain {scan_record['hostname']} has adequate validation life ({days} days remaining). State healthy."
    else:
        analysis["summary"] = f"Domain {scan_record['hostname']} is unreachable due to: {scan_record.get('failure_reason', 'Unknown Network Outage')}."
        
    return analysis

def mcp_ai_recommendation_tool(cert_record: dict) -> dict:
    """
    [MCP AI Recommendation Tool]
    Leverages the Groq API (llama3-8b-8192) to generate business-friendly impact reports, risk summaries,
    and remediation actions. If the GROQ_API_KEY is not defined, falls back to a high-quality expert-designed template generator.
    """
    hostname = cert_record["hostname"]
    status = cert_record["status"]
    days = cert_record["days_remaining"]
    issuer = cert_record.get("issuer") or "Unknown Certificate Authority"
    expiry_date = cert_record.get("expiry_date") or "N/A"
    
    # If the certificate is healthy, no remediation ticket is needed
    if status == "HEALTHY" or status == "UNREACHABLE":
        return {
            "business_impact": "None. Domain is operating normally or is unreachable.",
            "risk_summary": "No remediation actions required. Certificate possesses valid validation remaining.",
            "recommended_actions": [],
            "due_date": "N/A",
            "priority": "LOW"
        }

    # Configure priority and general dates
    priority = "CRITICAL" if status == "CRITICAL" else "MEDIUM"
    due_date = "Immediately or before expiry" if status == "CRITICAL" else "At least 7 days before expiry"

    api_key = os.getenv("GROQ_API_KEY")
    
    if api_key and api_key != "MY_GEMINI_API_KEY": # Skip dummy token
        try:
            prompt = f"""
            You are a cybersecurity audit officer and assistant. Analyze this SSL certificate warning and generate a professional security assessment:
            Hostname: {hostname}
            Status: {status}
            Days Remaining: {days}
            Issuer: {issuer}
            Expiry Date: {expiry_date}
            
            Format your entire answer as a single stringified JSON object containing these exact keys:
            "risk_summary": a business-friendly explanation of the security risk in exactly 3-4 sentences. Do not use complex technical jargon.
            "business_impact": a concise, bulleted list of 3-4 business consequences of letting this expire (e.g. browser warnings, transaction interruptions, trust damage).
            "recommended_actions": a numbered list of 4-5 recovery actions in professional enterprise phrasing.
            
            Ensure your response is raw JSON only. Do not wrap in markdown ```json blocks.
            """
            
            url = "https://api.groq.com/openai/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
            body = {
                "model": "llama3-8b-8192",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2
            }
            
            req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                resp_data = json.loads(response.read().decode("utf-8"))
                text_content = resp_data["choices"][0]["message"]["content"].strip()
                
                # Strip out possible markdown wrapper formatting
                if text_content.startswith("```"):
                    text_content = text_content.replace("```json", "").replace("```", "").strip()
                
                parsed = json.loads(text_content)
                return {
                    "risk_summary": parsed.get("risk_summary", ""),
                    "business_impact": parsed.get("business_impact", []),
                    "recommended_actions": parsed.get("recommended_actions", []),
                    "due_date": due_date,
                    "priority": priority
                }
        except Exception as e:
            # On breakdown, log error and trigger resilient beautiful backup template
            print(f"Groq API connection warning: {e}. Activating localized backup expert system.")

    # --- Local fallback engine ---
    if status == "CRITICAL":
        risk_summary = f"The SSL certificate for {hostname} is scheduled to expire in only {days} days on {expiry_date}. Once this certificate window expires, any incoming user browser requests will encounter secure HTTPS connection handshake errors. This will cause browsers to display red security warnings, completely blocking normal user navigation. Immediate renewal must be configured in your domain authority console as soon as possible."
        impact = [
            "Immediate customer navigation blocking via red web browser security alerts.",
            "Disruption of insecure transit lines, APIs, and transactional payment gateways.",
            "Severe public trust erosion and reputational damage.",
            "Loss of operational compliance and industry security standards."
        ]
        actions = [
            f"Login into the certificate administrative console or active Certificate Authority ({issuer})",
            "Generate a standard Certificate Signing Request (CSR) on your server host",
            "Submit renewal request and complete Domain Control Validation (DCV)",
            "Download newly minted server certificates containing full intermediate chains",
            "Install new certificates on webservers and restart load-balancer daemons"
        ]
    else:
        # WARNING state
        risk_summary = f"The secure SSL socket certificate for {hostname} is approaching its expiration marker in {days} days on {expiry_date}. While HTTPS encryption is currently active, early restoration checks are required to prevent emergency maintenance. Renewing the certificate prevents connection bottlenecks and safeguards business processes."
        impact = [
            "Risk of unplanned server outages and downtime outside of working shifts.",
            "Decline in search engine visibility (SEO) due to pending chain warnings.",
            "Subtle organizational bottlenecks during last-minute DNS validation shifts."
        ]
        actions = [
            "Schedule maintenance hours for security certificate validation and swap-outs",
            "Retrieve updated private keys or create a renewal ticket with your CA provider",
            "Acquire the renewed SSL certificate files from administrative panels",
            "Perform staging server trials before live production socket deployment",
            "Verify complete certificate path validation and browser handshakes"
        ]

    return {
        "risk_summary": risk_summary,
        "business_impact": impact,
        "recommended_actions": actions,
        "due_date": due_date,
        "priority": priority
    }

def mcp_markdown_report_generator_tool(certificates: list) -> str:
    """
    [MCP Markdown Report Generator Tool]
    Compiles scanned records into the mandatory 'ssl_renewal_workbook_timestamp.md' structure.
    Generates entries for CRITICAL and WARNING certificates only.
    """
    timestamp_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    report_md = f"# SSL Renewal Tasks Report\n\nGenerated On:\n{timestamp_now}\n\n"
    
    # Filter critical and warning only
    targets = [c for c in certificates if c.get("status") in ["CRITICAL", "WARNING"]]
    
    if not targets:
        report_md += "No critical or warming expiring certificates require remediation at this time.\n"
        return report_md
        
    for cert in targets:
        # Generate recommendations (will use fallback or Groq depending on state)
        recs = mcp_ai_recommendation_tool(cert)
        
        hostname = cert["hostname"]
        status = cert["status"]
        issuer = cert.get("issuer") or "Unknown"
        expiry_date = cert.get("expiry_date") or "N/A"
        days_remaining = cert.get("days_remaining", -1)
        
        # Risk Explanation
        raw_summary = recs["risk_summary"]
        
        # Business Impact mapping
        impact_bullets = ""
        impacts = recs["business_impact"]
        if isinstance(impacts, list):
            for imp in impacts:
                impact_bullets += f"* {imp}\n"
        else:
            impact_bullets += f"* {impacts}\n"
            
        # Recommended Actions
        actions_list = ""
        actions = recs["recommended_actions"]
        if isinstance(actions, list):
            for idx, act in enumerate(actions, 1):
                actions_list += f"{idx}. {act}\n"
        else:
            actions_list += f"1. {actions}\n"
            
        due_date = recs["due_date"]
        priority = recs["priority"]
        
        # Email expiration dates
        try:
            exp_date_obj = datetime.fromisoformat(expiry_date.replace("Z", ""))
            readable_exp_date = exp_date_obj.strftime("%B %d, %Y")
        except Exception:
            readable_exp_date = expiry_date
            
        # Compile entry
        entry_md = f"""---

## [{status}] {hostname}

### Certificate Details

Hostname:
{hostname}
Issuer:
{issuer}
Expiry Date:
{expiry_date}
Days Remaining:
{days_remaining}
Priority:
{priority}

### Risk Summary

{raw_summary}

### Business Impact

{impact_bullets}
### Recommended Actions

{actions_list}
### Due Date

{due_date}

### Email Draft

Subject:
SSL Certificate Renewal Required - {hostname}

Hello Team,

The SSL certificate for {hostname} is scheduled to expire on {readable_exp_date} and currently has {days_remaining} days remaining.

Please initiate the renewal process and complete deployment before the expiry date to avoid service interruptions and browser security warnings.

Recommended completion date:
{due_date}

Regards,
ExpirySense
"""
        report_md += entry_md
        
    return report_md

def mcp_csv_export_tool(certificates: list) -> str:
    """
    [MCP CSV Export Tool]
    Compiles all certificate states into standard, highly robust, comma-separated sheets.
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    
    # Headers
    writer.writerow([
        "Hostname", "Issuer", "Expiry Date", "Days Remaining", "TLS Version", "Status", "Last Scan Time"
    ])
    
    for cert in certificates:
        writer.writerow([
            cert["hostname"],
            cert.get("issuer") or "N/A",
            cert.get("expiry_date") or "N/A",
            cert.get("days_remaining", -1),
            cert.get("tls_version") or "N/A",
            cert["status"],
            cert.get("last_scan") or "N/A"
        ])
        
    return output.getvalue()
