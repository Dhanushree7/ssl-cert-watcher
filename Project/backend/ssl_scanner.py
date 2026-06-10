# ExpirySense SSL/TLS Certificate Scanner Engine
import socket
import ssl
import time
from datetime import datetime, timezone

def extract_issuer_name(issuer_tuple):
    """Safely decodes commonName or organizationName from certificate issuer tuple."""
    if not issuer_tuple:
        return "Unknown Issuer"
    
    # First priority: Common Name (CN)
    for rdn in issuer_tuple:
        for entry in rdn:
            if entry[0] == 'commonName':
                return entry[1]
                
    # Second priority: Organization (O)
    for rdn in issuer_tuple:
        for entry in rdn:
            if entry[0] == 'organizationName':
                return entry[1]
                
    # Fallback to any present attribute value
    try:
        return issuer_tuple[0][0][1]
    except Exception:
        return "Unknown Issuer"

def scan_ssl_certificate(hostname: str, timeout: int = 5) -> dict:
    """
    Executes live SSL scanning for any supplied hostname on port 443.
    Extracts SSL details or handles connection failures with precise reasons.
    """
    result = {
        "hostname": hostname,
        "issuer": None,
        "expiry_date": None,
        "days_remaining": -1,
        "tls_version": None,
        "status": "UNREACHABLE",
        "failure_reason": None
    }
    
    # Clean hostname (strips schemas or slash dividers)
    host = hostname.strip().lower()
    if "://" in host:
        host = host.split("://")[1]
    host = host.split("/")[0]
    host = host.split(":")[0]
    
    # 1. DNS Resolution
    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        result["failure_reason"] = "DNS Resolution Failed"
        return result
        
    # 2. Establish Connection & Negotiate SSL Handshake
    context = ssl.create_default_context()
    # Ensure standard checks
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    
    try:
        # Create standard TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Connect over SSL
        ssock = context.wrap_socket(sock, server_hostname=host)
        ssock.connect((host, 443))
        
        # Extract peer certificate
        cert = ssock.getpeercert()
        tls_version = ssock.version()
        
        ssock.close()
        
        if not cert:
            result["failure_reason"] = "No SSL Certificate Found"
            return result
            
        # Parse Expiry Time
        expiry_epoch = ssl.cert_time_to_seconds(cert.get("notAfter"))
        expiry_datetime = datetime.fromtimestamp(expiry_epoch, tz=timezone.utc)
        expiry_date_str = expiry_datetime.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
        
        # Calculate days remaining
        remaining_seconds = expiry_epoch - time.time()
        days_remaining = int(remaining_seconds / (24 * 3600))
        
        # Extract Issuer Name
        issuer_raw = cert.get("issuer")
        issuer_name = extract_issuer_name(issuer_raw)
        
        # Risk levels computation
        if days_remaining <= 14:
            status = "CRITICAL"
        elif days_remaining <= 45:
            status = "WARNING"
        else:
            status = "HEALTHY"
            
        result.update({
            "issuer": issuer_name,
            "expiry_date": expiry_date_str,
            "days_remaining": days_remaining,
            "tls_version": tls_version,
            "status": status
        })
        
    except socket.timeout:
        result["failure_reason"] = "Connection Timeout"
    except ConnectionRefusedError:
        result["failure_reason"] = "Connection Refused"
    except ssl.SSLError as ssl_err:
        result["failure_reason"] = "SSL Handshake Failed"
    except Exception as general_err:
        result["failure_reason"] = f"Verification Failed ({str(general_err)})"
        
    return result
# Self-test routine
if __name__ == "__main__":
    print(scan_ssl_certificate("google.com"))
    print(scan_ssl_certificate("expired.badssl.com"))
