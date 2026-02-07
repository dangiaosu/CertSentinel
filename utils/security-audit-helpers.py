"""
Security Audit Helper Utilities

Provides formatting and utility functions for security audit reports
"""

from typing import Dict, List, Any


def format_security_report(audit_result: Dict[str, Any]) -> str:
    """
    Format security audit result into readable text report

    Args:
        audit_result: Result from perform_security_audit()

    Returns:
        Formatted text report
    """
    domain = audit_result.get('domain', 'Unknown')
    grade = audit_result.get('score', 'F')
    numeric_score = audit_result.get('numeric_score', 0)

    report = f"🔒 **Security Audit Report: {domain}**\n\n"
    report += f"**Overall Score: {grade} ({numeric_score}/100)**\n\n"

    # Headers section
    headers_audit = audit_result.get('headers_audit', {})
    headers_found = headers_audit.get('headers_found', {})
    headers_missing = headers_audit.get('headers_missing', [])

    report += "**Security Headers:**\n"
    if headers_found:
        report += f"✅ Found: {len(headers_found)}/5\n"
        for header, value in headers_found.items():
            report += f"  • {header}: {value[:50]}...\n" if len(value) > 50 else f"  • {header}: {value}\n"
    else:
        report += "❌ No security headers found\n"

    if headers_missing:
        report += f"\n⚠️ Missing: {len(headers_missing)}/5\n"
        for missing in headers_missing:
            report += f"  • {missing['header']} ({missing['severity']})\n"

    # Ports section
    ports_audit = audit_result.get('ports_audit', {})
    open_ports = ports_audit.get('open_ports', [])

    report += "\n**Port Scan Results:**\n"
    if open_ports:
        report += f"🔴 **DANGER: {len(open_ports)} dangerous ports open!**\n"
        for port_info in open_ports:
            report += f"  • Port {port_info['port']} ({port_info['service']}): OPEN\n"
    else:
        report += "✅ No dangerous ports detected\n"

    # Recommendations
    recommendations = audit_result.get('recommendations', [])
    if recommendations:
        report += "\n**Recommendations:**\n"
        for rec in recommendations[:5]:  # Limit to top 5
            report += f"{rec}\n"

    return report


def get_security_score_emoji(grade: str) -> str:
    """
    Get emoji for security grade

    Args:
        grade: Letter grade (A-F)

    Returns:
        Emoji representing the grade
    """
    emoji_map = {
        'A': '🟢',
        'B': '🟡',
        'C': '🟠',
        'D': '🔴',
        'F': '⛔'
    }
    return emoji_map.get(grade, '❓')


def is_critical_security_issue(audit_result: Dict[str, Any]) -> bool:
    """
    Check if audit result contains critical security issues

    Args:
        audit_result: Result from perform_security_audit()

    Returns:
        True if critical issues detected
    """
    # Critical if grade is D or F
    if audit_result.get('score') in ['D', 'F']:
        return True

    # Critical if any dangerous ports are open
    ports_audit = audit_result.get('ports_audit', {})
    if ports_audit.get('open_ports'):
        return True

    # Critical if missing high-severity headers
    headers_audit = audit_result.get('headers_audit', {})
    headers_missing = headers_audit.get('headers_missing', [])
    high_severity_missing = [h for h in headers_missing if h.get('severity') == 'high']

    return len(high_severity_missing) >= 2


def get_port_risk_level(port: int) -> str:
    """
    Get risk level for specific port

    Args:
        port: Port number

    Returns:
        Risk level: 'high', 'medium', or 'low'
    """
    high_risk_ports = [22, 23, 3389]  # SSH, Telnet, RDP
    medium_risk_ports = [21, 3306, 5432, 6379, 27017]  # FTP, databases

    if port in high_risk_ports:
        return 'high'
    elif port in medium_risk_ports:
        return 'medium'
    else:
        return 'low'
