# ExpirySense FastAPI Main Server Core
import os
import sys
import re
from datetime import datetime
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

# Resolve pathing
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import init_db, save_certificate_record, get_all_certificates, delete_certificate_record
from backend.ai_agent import ExpirySenseAgent
from backend.models import HostnamesInput

# Spawn FastAPI instance
app = FastAPI(
    title="ExpirySense API",
    description="SSL Certificate Expiry Watcher full-stack service with MCP & Groq",
    version="1.0.0"
)

# CORS Middleware configurations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize AI Orchestrator Agent
agent = ExpirySenseAgent()

# Regular expression for hostname structure assertions
HOSTNAME_REGEX = re.compile(
    r"^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$"
)

def clean_and_validate_hostname(raw: str) -> str:
    """Pre-processes input URL domains into rigid clean host addresses."""
    host = raw.strip().lower()
    # Strip protocols
    if "://" in host:
        host = host.split("://")[1]
    host = host.split("/")[0]
    host = host.split(":")[0]
    
    if not HOSTNAME_REGEX.match(host):
        raise ValueError(f"Invalid hostname format: '{raw}'")
    return host

@app.on_event("startup")
def on_startup():
    """Initializes telemetry SQLite engine on app start."""
    init_db()

# --- API Endpoints ---

@app.post("/api/scan-hostnames", status_code=status.HTTP_200_OK)
def scan_hostnames(payload: HostnamesInput):
    """
    Executes live SSL scans on hostnames parameter list. 
    Synchronizes results with the SQLite log.
    """
    if not payload.hostnames:
        raise HTTPException(
            status_code=400, 
            detail="Hostnames query list cannot be empty."
        )

    processed_list = []
    skipped_list = []

    for hostname in payload.hostnames:
        try:
            valid_host = clean_and_validate_hostname(hostname)
            processed_list.append(valid_host)
        except ValueError:
            skipped_list.append(hostname)

    if not processed_list:
        raise HTTPException(
            status_code=400,
            detail=f"All provided hostnames failed validation checks, e.g. '{payload.hostnames[0]}'"
        )

    deduplicated = list(set(processed_list))
    scan_results = []

    # Run AI Scanning and audit routines
    for host in deduplicated:
        try:
            # AI Agent encapsulates SSL scanning inside its registered MCP tool
            scan_record = agent.execute_hostname_scan(host)
            
            # Persist under SQLite logs
            save_certificate_record(scan_record)
            scan_results.append(scan_record)
        except Exception as e:
            # Fallback error record
            err_record = {
                "hostname": host,
                "status": "UNREACHABLE",
                "failure_reason": f"System Interruption ({str(e)})"
            }
            save_certificate_record(err_record)
            scan_results.append(err_record)

    return {
        "message": f"Successfully completed secure verification audits on {len(scan_results)} domain(s).",
        "scanned": [c["hostname"] for c in scan_results],
        "skipped": skipped_list
    }

@app.get("/api/certificates")
def get_recorded_certificates():
    """Retrieves list of all saved certificates log records."""
    return get_all_certificates()

@app.delete("/api/certificates/{cert_id}")
def delete_recorded_certificate(cert_id: int):
    """Deletes certificate record from SQLite datastore."""
    success = delete_certificate_record(cert_id)
    if not success:
        raise HTTPException(
            status_code=404,
            detail=f"Certificate log entry with ID {cert_id} not found."
        )
    return {"message": "Hostname deleted successfully"}

@app.get("/api/export/csv")
def export_certificates_as_csv():
    """Compiles all certificate telemetry logs into a dynamic downloadable CSV file attachment."""
    certs = get_all_certificates()
    csv_payload = agent.compile_csv_report(certs)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ssl_scan_report_{timestamp}.csv"
    
    headers = {
        "Content-Disposition": f"attachment; filename={filename}"
    }
    return Response(content=csv_payload, media_type="text/csv", headers=headers)

@app.get("/api/export/markdown")
def export_certificates_as_markdown():
    """
    Compiles AI Remediation Workbooks containing actionable recovery mail copies 
    for warning and critical level certificates.
    """
    certs = get_all_certificates()
    md_payload = agent.compile_markdown_workbook(certs)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ssl_renewal_workbook_{timestamp}.md"
    
    # Also save to public file reports path as target
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(__abspath__ if '__abspath__' in locals() else __file__)), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    report_file_path = os.path.join(reports_dir, "renewal_tasks.md")
    with open(report_file_path, "w", encoding="utf-8") as f:
        f.write(md_payload)
        
    headers = {
        "Content-Disposition": f"attachment; filename={filename}"
    }
    return Response(content=md_payload, media_type="text/markdown", headers=headers)

# Static Files Router Mount
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    # Serves the full stack application directly on Port 3000!
    uvicorn.run("backend.main:app", host="0.0.0.0", port=3000, reload=True)
