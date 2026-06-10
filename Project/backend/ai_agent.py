# ExpirySense AI Agent Layer
import json
import os
from datetime import datetime, timezone
from backend.mcp_server import call_mcp_tool

class ExpirySenseAgent:
    """
    High-level Secure AI Agent executing audits on SSL Cert telemetry.
    All operations MUST invoke MCP server tools instead of accessing backend modules directly.
    """
    
    def __init__(self):
        self.model = "llama3-8b-8192"
        self.last_run_time = None

    def execute_hostname_scan(self, hostname: str) -> dict:
        """Runs scan of domain using the registered 'ssl_scanner_tool' MCP tool."""
        print(f"[AI Agent] Invoking MCP tool 'ssl_scanner_tool' for host: {hostname}")
        # Call tool via MCP server dispatcher
        mcp_response = call_mcp_tool(
            "ssl_scanner_tool", 
            {"hostname": hostname}
        )
        # Extract returned payload text
        json_txt = mcp_response["content"][0]["text"]
        return json.loads(json_txt)

    def analyze_certificate_severity(self, scan_record: dict) -> dict:
        """Gathers risk assessments from the 'certificate_analyzer_tool' MCP tool."""
        print(f"[AI Agent] Invoking MCP tool 'certificate_analyzer_tool' for host: {scan_record['hostname']}")
        mcp_response = call_mcp_tool(
            "certificate_analyzer_tool",
            {"scan_record": scan_record}
        )
        json_txt = mcp_response["content"][0]["text"]
        return json.loads(json_txt)

    def generate_remediation_details(self, cert_record: dict) -> dict:
        """Creates specialized remedy instructions through 'ai_recommendation_tool' MCP tool."""
        print(f"[AI Agent] Invoking MCP tool 'ai_recommendation_tool' for host: {cert_record['hostname']}")
        mcp_response = call_mcp_tool(
            "ai_recommendation_tool", 
            {"cert_record": cert_record}
        )
        json_txt = mcp_response["content"][0]["text"]
        return json.loads(json_txt)

    def compile_markdown_workbook(self, certificates: list) -> str:
        """Builds cohesive markdown workbook document using 'markdown_report_generator_tool' MCP tool."""
        print(f"[AI Agent] Invoking MCP tool 'markdown_report_generator_tool' for {len(certificates)} certificates.")
        mcp_response = call_mcp_tool(
            "markdown_report_generator_tool",
            {"certificates": certificates}
        )
        return mcp_response["content"][0]["text"]

    def compile_csv_report(self, certificates: list) -> str:
        """Formats tabular comma-separated columns using the 'csv_export_tool' MCP tool."""
        print(f"[AI Agent] Invoking MCP tool 'csv_export_tool' for {len(certificates)} certificates.")
        mcp_response = call_mcp_tool(
            "csv_export_tool",
            {"certificates": certificates}
        )
        return mcp_response["content"][0]["text"]
