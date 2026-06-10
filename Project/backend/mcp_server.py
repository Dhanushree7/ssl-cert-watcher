# ExpirySense Model Context Protocol (MCP) Server Layer
import sys
import json
import traceback
from backend import mcp_tools

def list_mcp_tools():
    """Returns schemas for the five registered MCP tools."""
    return {
        "tools": [
            {
                "name": "ssl_scanner_tool",
                "description": "Scans SSL/TLS socket for a supplied hostname on port 443, returning raw TLS cert descriptors.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "hostname": {"type": "string", "description": "Clean domain address (e.g. 'google.com')."}
                    },
                    "required": ["hostname"]
                }
            },
            {
                "name": "certificate_analyzer_tool",
                "description": "Evaluates days remaining and status parameters on any scan record to assign severity levels.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scan_record": {"type": "object", "description": "Raw scan record dictionary."}
                    },
                    "required": ["scan_record"]
                }
            },
            {
                "name": "ai_recommendation_tool",
                "description": "Calls Groq API (llama3-8b-8192) to generate security risks, business impacts, and recovery bullet points.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cert_record": {"type": "object", "description": "Target cert record."}
                    },
                    "required": ["cert_record"]
                }
            },
            {
                "name": "markdown_report_generator_tool",
                "description": "Takes a list of active certificates and generates a business-ready SSL renewal workbook (.md) file content.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "certificates": {"type": "array", "description": "Array of active database certificates."}
                    },
                    "required": ["certificates"]
                }
            },
            {
                "name": "csv_export_tool",
                "description": "Assembles a bulk list of active certificates into a tabular CSV report content structure.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "certificates": {"type": "array", "description": "Array of active database certificates."}
                    },
                    "required": ["certificates"]
                }
            }
        ]
    }

def call_mcp_tool(name: str, arguments: dict):
    """Dispatches tool execution request to corresponding underlying python function."""
    if name == "ssl_scanner_tool":
        hostname = arguments.get("hostname")
        if not hostname:
            raise ValueError("hostname argument is required")
        return {"content": [{"type": "text", "text": json.dumps(mcp_tools.mcp_ssl_scanner_tool(hostname))}]}
        
    elif name == "certificate_analyzer_tool":
        record = arguments.get("scan_record")
        if not record:
            raise ValueError("scan_record argument is required")
        return {"content": [{"type": "text", "text": json.dumps(mcp_tools.mcp_certificate_analyzer_tool(record))}]}
        
    elif name == "ai_recommendation_tool":
        record = arguments.get("cert_record")
        if not record:
            raise ValueError("cert_record argument is required")
        return {"content": [{"type": "text", "text": json.dumps(mcp_tools.mcp_ai_recommendation_tool(record))}]}
        
    elif name == "markdown_report_generator_tool":
        certs = arguments.get("certificates")
        if certs is None:
            raise ValueError("certificates argument is required")
        return {"content": [{"type": "text", "text": mcp_tools.mcp_markdown_report_generator_tool(certs)}]}
        
    elif name == "csv_export_tool":
        certs = arguments.get("certificates")
        if certs is None:
            raise ValueError("certificates argument is required")
        return {"content": [{"type": "text", "text": mcp_tools.mcp_csv_export_tool(certs)}]}
        
    else:
        raise ValueError(f"Unknown MCP Tool: '{name}'")

def start_stdio_mcp_server():
    """Runs a standard micro MCP JSON-RPC Server over sys.stdin / sys.stdout."""
    print("ExpirySense MCP Server initialized. Awaiting stdio connection protocol...", file=sys.stderr)
    
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
            req_id = request.get("id")
            method = request.get("method")
            params = request.get("params", {})
            
            # Formulating output RPC standard
            response = {
                "jsonrpc": "2.0",
                "id": req_id
            }
            
            if method == "tools/list":
                response["result"] = list_mcp_tools()
            elif method == "tools/call":
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})
                response["result"] = call_mcp_tool(tool_name, tool_args)
            elif method == "ping":
                response["result"] = {}
            else:
                response["error"] = {
                    "code": -32601,
                    "message": f"Method {method} not defined in ExpirySense MCP"
                }
                
            print(json.dumps(response), flush=True)
            
        except Exception as err:
            err_response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32603,
                    "message": str(err),
                    "data": traceback.format_exc()
                }
            }
            print(json.dumps(err_response), flush=True)

if __name__ == "__main__":
    start_stdio_mcp_server()
