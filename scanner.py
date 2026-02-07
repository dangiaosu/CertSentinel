"""
Security Scanner Module

Provides security audit functionality including:
- HTTP security headers checking
- Dangerous port scanning
- Security scoring and grading system
"""

import requests
import socket
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

# Security headers to check
SECURITY_HEADERS = {
    'strict-transport-security': {
        'name': 'Strict-Transport-Security',
        'severity': 'high',
        'description': 'Forces HTTPS connections'
    },
    'x-frame-options': {
        'name': 'X-Frame-Options',
        'severity': 'medium',
        'description': 'Prevents clickjacking attacks'
    },
    'x-content-type-options': {
        'name': 'X-Content-Type-Options',
        'severity': 'medium',
        'description': 'Prevents MIME sniffing'
    },
    'content-security-policy': {
        'name': 'Content-Security-Policy',
        'severity': 'high',
        'description': 'Controls resource loading'
    },
    'x-xss-protection': {
        'name': 'X-XSS-Protection',
        'severity': 'low',
        'description': 'Legacy XSS protection'
    }
}

# Dangerous ports to scan (as per requirements: common ports only)
DANGEROUS_PORTS = {
    22: 'SSH',
    80: 'HTTP',
    443: 'HTTPS',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    6379: 'Redis',
    27017: 'MongoDB'
}


def check_security_headers(url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Check HTTP security headers for a URL

    Args:
        url: Target URL to check
        timeout: Request timeout in seconds

    Returns:
        {
            "url": str,
            "status_code": int,
            "headers_found": {...},
            "headers_missing": [...],
            "issues": [...],
            "score": int (0-100)
        }
    """
    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={'User-Agent': 'CertSentinel-Bot/1.0'}
        )

        headers_found = {}
        headers_missing = []
        issues = []

        # Check each security header
        for header_key, header_info in SECURITY_HEADERS.items():
            header_value = response.headers.get(header_info['name'])

            if header_value:
                headers_found[header_info['name']] = header_value

                # Validate header values
                if header_key == 'x-frame-options':
                    if header_value.upper() not in ['DENY', 'SAMEORIGIN']:
                        issues.append({
                            'header': header_info['name'],
                            'severity': 'medium',
                            'issue': f'Weak value: {header_value}'
                        })

                elif header_key == 'x-content-type-options':
                    if header_value.lower() != 'nosniff':
                        issues.append({
                            'header': header_info['name'],
                            'severity': 'low',
                            'issue': f'Expected "nosniff", got: {header_value}'
                        })

            else:
                headers_missing.append({
                    'header': header_info['name'],
                    'severity': header_info['severity'],
                    'description': header_info['description']
                })

        # Calculate score
        total_headers = len(SECURITY_HEADERS)
        found_headers = len(headers_found)
        score = int((found_headers / total_headers) * 100)

        # Deduct points for issues
        score -= len(issues) * 10

        return {
            "url": url,
            "status_code": response.status_code,
            "headers_found": headers_found,
            "headers_missing": headers_missing,
            "issues": issues,
            "score": max(0, score)
        }

    except requests.Timeout:
        logger.error(f"Timeout checking headers for {url}")
        return {
            "url": url,
            "error": "Request timeout",
            "score": 0
        }

    except requests.RequestException as e:
        logger.error(f"Error checking headers for {url}: {e}")
        return {
            "url": url,
            "error": f"Request failed: {str(e)}",
            "score": 0
        }

    except Exception as e:
        logger.error(f"Unexpected error checking headers for {url}: {e}")
        return {
            "url": url,
            "error": f"Unexpected error: {str(e)}",
            "score": 0
        }


def scan_single_port(host: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Scan a single port on host

    Args:
        host: Target host IP or hostname
        port: Port number to scan
        timeout: Socket timeout in seconds

    Returns:
        {
            "port": int,
            "service": str,
            "status": "open" | "closed" | "filtered"
        }
    """
    try:
        # Validate port range
        if not isinstance(port, int) or port < 1 or port > 65535:
            return {"port": port, "service": "Invalid", "status": "error"}

        # Validate hostname format
        if not host or not isinstance(host, str) or len(host) > 255:
            return {"port": port, "service": "Invalid host", "status": "error"}

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        service = DANGEROUS_PORTS.get(port, f'Port {port}')

        if result == 0:
            return {"port": port, "service": service, "status": "open"}
        else:
            return {"port": port, "service": service, "status": "closed"}

    except socket.timeout:
        return {"port": port, "service": DANGEROUS_PORTS.get(port, f'Port {port}'), "status": "filtered"}

    except socket.gaierror:
        return {"port": port, "service": DANGEROUS_PORTS.get(port, f'Port {port}'), "status": "error", "error": "DNS resolution failed"}

    except Exception as e:
        logger.error(f"Error scanning port {port} on {host}: {e}")
        return {"port": port, "service": DANGEROUS_PORTS.get(port, f'Port {port}'), "status": "error", "error": str(e)}


def scan_dangerous_ports(host: str, timeout: float = 2.0, max_workers: int = 10) -> Dict[str, Any]:
    """
    Scan dangerous ports on host using ThreadPoolExecutor

    Args:
        host: Target host to scan
        timeout: Per-port timeout in seconds
        max_workers: Maximum concurrent threads

    Returns:
        {
            "host": str,
            "ip": str,
            "open_ports": [...],
            "closed_ports": [...],
            "filtered_ports": [...],
            "critical_count": int
        }
    """
    try:
        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return {
                "host": host,
                "error": "DNS resolution failed",
                "open_ports": [],
                "closed_ports": [],
                "filtered_ports": []
            }

        open_ports = []
        closed_ports = []
        filtered_ports = []

        # Scan ports in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(scan_single_port, ip, port, timeout): port
                for port in DANGEROUS_PORTS.keys()
            }

            for future in futures:
                result = future.result()

                if result['status'] == 'open':
                    open_ports.append(result)
                elif result['status'] == 'closed':
                    closed_ports.append(result)
                elif result['status'] == 'filtered':
                    filtered_ports.append(result)

        return {
            "host": host,
            "ip": ip,
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "filtered_ports": filtered_ports,
            "critical_count": len(open_ports)
        }

    except Exception as e:
        logger.error(f"Error scanning ports for {host}: {e}")
        return {
            "host": host,
            "error": f"Port scan failed: {str(e)}",
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": []
        }


async def perform_security_audit(domain: str) -> Dict[str, Any]:
    """
    Perform complete security audit: headers + port scan

    Args:
        domain: Target domain to audit

    Returns:
        {
            "domain": str,
            "score": "A" | "B" | "C" | "D" | "F",
            "numeric_score": int,
            "headers_audit": {...},
            "ports_audit": {...},
            "recommendations": [...],
            "timestamp": str,
            "check_duration": float
        }
    """
    start_time = datetime.now()

    # Remove protocol from domain if present
    domain_clean = domain.replace('https://', '').replace('http://', '').split('/')[0]

    # Run headers check (synchronous)
    headers_result = check_security_headers(f'https://{domain_clean}')

    # Run port scan (synchronous but uses ThreadPoolExecutor internally)
    loop = asyncio.get_event_loop()
    ports_result = await loop.run_in_executor(
        None,
        scan_dangerous_ports,
        domain_clean
    )

    # Calculate overall score
    header_score = headers_result.get('score', 0)
    port_penalty = ports_result.get('critical_count', 0) * 15  # -15 per open dangerous port

    total_score = max(0, header_score - port_penalty)

    # Convert to letter grade
    if total_score >= 90:
        grade = 'A'
    elif total_score >= 75:
        grade = 'B'
    elif total_score >= 60:
        grade = 'C'
    elif total_score >= 40:
        grade = 'D'
    else:
        grade = 'F'

    # Generate recommendations
    recommendations = []

    # Header recommendations
    for missing in headers_result.get('headers_missing', []):
        if missing['severity'] == 'high':
            recommendations.append(f"🔴 CRITICAL: Add {missing['header']} header")
        elif missing['severity'] == 'medium':
            recommendations.append(f"🟡 WARNING: Add {missing['header']} header")
        else:
            recommendations.append(f"🔵 INFO: Consider adding {missing['header']} header")

    # Port recommendations
    for open_port in ports_result.get('open_ports', []):
        recommendations.append(
            f"⚠️ SECURITY RISK: {open_port['service']} (port {open_port['port']}) is publicly accessible"
        )

    # Success messages
    if not ports_result.get('open_ports'):
        recommendations.append("✅ No dangerous ports detected")

    if header_score >= 80:
        recommendations.append("✅ Good security header coverage")

    check_duration = (datetime.now() - start_time).total_seconds()

    return {
        "domain": domain_clean,
        "score": grade,
        "numeric_score": total_score,
        "headers_audit": headers_result,
        "ports_audit": ports_result,
        "recommendations": recommendations,
        "timestamp": datetime.now().isoformat(),
        "check_duration": check_duration
    }


async def test_security_audit():
    """Test security audit functionality"""
    print("Testing security audit for google.com...")
    result = await perform_security_audit('google.com')

    print(f"\nDomain: {result['domain']}")
    print(f"Score: {result['score']} ({result['numeric_score']}/100)")
    print(f"\nHeaders Found: {len(result['headers_audit'].get('headers_found', {}))}")
    print(f"Headers Missing: {len(result['headers_audit'].get('headers_missing', []))}")
    print(f"Open Ports: {len(result['ports_audit'].get('open_ports', []))}")

    print("\nRecommendations:")
    for rec in result['recommendations']:
        # Handle Unicode on Windows terminal
        try:
            print(f"  {rec}")
        except UnicodeEncodeError:
            print(f"  {rec.encode('ascii', 'ignore').decode('ascii')}")


if __name__ == '__main__':
    import asyncio
    asyncio.run(test_security_audit())
