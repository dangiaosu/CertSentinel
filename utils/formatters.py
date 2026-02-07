"""
Message formatters for CertSentinel bot.
Handles emoji-rich Telegram messages with markdown formatting.
"""

from datetime import datetime
from typing import Dict, List, Any, Optional


def escape_markdown(text: str) -> str:
    """
    Escape markdown special characters for Telegram MarkdownV2.

    Args:
        text: Text to escape

    Returns:
        Escaped text safe for Telegram markdown
    """
    special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
    for char in special_chars:
        text = text.replace(char, f'\\{char}')
    return text


def format_domain_list(domains: List[Dict[str, Any]]) -> str:
    """
    Format list of domains for display.

    Args:
        domains: List of domain dicts with status info

    Returns:
        Formatted markdown string
    """
    if not domains:
        return "📋 No domains currently monitored"

    response = "📋 **Monitored Domains:**\n\n"

    for domain in domains:
        name = domain.get('domain_name', 'Unknown')
        enabled = domain.get('enabled', 1)

        status_emoji = "🟢" if enabled else "⏸️"
        response += f"{status_emoji} **{name}**\n"

        # Add last check times if available
        if domain.get('last_uptime_check'):
            response += f"  Last uptime check: {domain['last_uptime_check']}\n"
        if domain.get('last_ssl_check'):
            response += f"  Last SSL check: {domain['last_ssl_check']}\n"

        response += "\n"

    return response


def format_alert(alert_type: str, domain: str, details: Dict[str, Any]) -> str:
    """
    Format alert message with appropriate emoji.

    Args:
        alert_type: 'ssl_expiry', 'uptime_down', 'domain_expiry', 'latency'
        domain: Domain name
        details: Alert-specific details

    Returns:
        Formatted alert message
    """
    emoji_map = {
        'ssl_expiry': '⚠️',
        'uptime_down': '🔴',
        'domain_expiry': '⏰',
        'latency': '🐌'
    }

    emoji = emoji_map.get(alert_type, '⚠️')

    if alert_type == 'ssl_expiry':
        days = details.get('days_remaining', 0)
        return (
            f"{emoji} **SSL Certificate Expiring Soon!**\n\n"
            f"Domain: **{domain}**\n"
            f"Days Remaining: **{days}**\n"
            f"Expiry Date: {details.get('expiry_date', 'Unknown')}\n"
            f"Issuer: {details.get('issuer', 'Unknown')}\n\n"
            f"Action Required: Renew certificate before expiry"
        )

    elif alert_type == 'uptime_down':
        status_code = details.get('status_code', 'N/A')
        error = details.get('error', 'Unknown error')
        return (
            f"{emoji} **Website Down!**\n\n"
            f"Domain: **{domain}**\n"
            f"Status: **DOWN**\n"
            f"Status Code: {status_code}\n"
            f"Error: {error}\n"
            f"Timestamp: {details.get('timestamp', datetime.now().isoformat())}\n\n"
            f"Action Required: Check website immediately"
        )

    elif alert_type == 'domain_expiry':
        days = details.get('days_remaining', 0)
        return (
            f"{emoji} **Domain Registration Expiring!**\n\n"
            f"Domain: **{domain}**\n"
            f"Days Remaining: **{days}**\n"
            f"Expiry Date: {details.get('expiry_date', 'Unknown')}\n"
            f"Registrar: {details.get('registrar', 'Unknown')}\n\n"
            f"Action Required: Renew domain registration"
        )

    elif alert_type == 'latency':
        response_time = details.get('response_time', 0)
        return (
            f"{emoji} **High Latency Detected!**\n\n"
            f"Domain: **{domain}**\n"
            f"Response Time: **{response_time}s**\n"
            f"Threshold: 2s\n"
            f"Timestamp: {details.get('timestamp', datetime.now().isoformat())}\n\n"
            f"Info: Website is slow but operational"
        )

    else:
        return f"{emoji} **Alert for {domain}**: {str(details)}"


def format_scan_result(scan_type: str, result: Dict[str, Any]) -> str:
    """
    Format scan result for display.

    Args:
        scan_type: 'ssl', 'uptime', 'domain', 'security_audit'
        result: Scan result dict

    Returns:
        Formatted result message
    """
    domain = result.get('domain', result.get('url', 'Unknown'))

    if scan_type == 'ssl':
        status = result.get('status', 'error')
        data = result.get('data', {})

        if status == 'error':
            return f"❌ SSL check failed for **{domain}**: {result.get('error', 'Unknown error')}"

        days = data.get('days_remaining', 'Unknown')
        expiry = data.get('expiry_date', 'Unknown')
        issuer = data.get('issuer', 'Unknown')

        status_emoji = "✅" if status == 'ok' else "⚠️"

        return (
            f"{status_emoji} **SSL Certificate Status: {domain}**\n\n"
            f"Days Remaining: **{days}**\n"
            f"Expiry Date: {expiry}\n"
            f"Issuer: {issuer}\n"
            f"Status: {status.upper()}"
        )

    elif scan_type == 'uptime':
        status = result.get('status', 'error')
        data = result.get('data', {})

        status_emoji = "🟢" if status == 'up' else "🔴"
        status_code = data.get('status_code', 'N/A')
        response_time = data.get('response_time', 'N/A')

        return (
            f"{status_emoji} **Uptime Status: {domain}**\n\n"
            f"Status: **{status.upper()}**\n"
            f"Status Code: {status_code}\n"
            f"Response Time: {response_time}s\n"
        )

    elif scan_type == 'domain':
        status = result.get('status', 'error')
        data = result.get('data', {})

        if status == 'error':
            return f"❌ Domain check failed for **{domain}**: {result.get('error', 'Unknown error')}"

        days = data.get('days_remaining', 'Unknown')
        expiry = data.get('expiry_date', 'Unknown')
        registrar = data.get('registrar', 'Unknown')

        status_emoji = "✅" if status == 'ok' else "⚠️"

        return (
            f"{status_emoji} **Domain Registration: {domain}**\n\n"
            f"Days Until Expiry: **{days}**\n"
            f"Expiry Date: {expiry}\n"
            f"Registrar: {registrar}\n"
            f"Status: {status.upper()}"
        )

    else:
        return f"📊 **Scan Result ({scan_type})**: {str(result)}"


def format_error(error_msg: str, context: str = None) -> str:
    """
    Format error message for user display.

    Args:
        error_msg: Error message
        context: Optional context about what failed

    Returns:
        Formatted error message
    """
    response = "❌ **Error Occurred**\n\n"

    if context:
        response += f"Context: {context}\n"

    response += f"Details: {error_msg}\n\n"
    response += "Please try again or contact support if the issue persists."

    return response


def format_success(message: str, details: Optional[str] = None) -> str:
    """
    Format success message.

    Args:
        message: Success message
        details: Optional additional details

    Returns:
        Formatted success message
    """
    response = f"✅ {message}"

    if details:
        response += f"\n\n{details}"

    return response


def format_monitoring_summary(domains: List[Dict[str, Any]]) -> str:
    """
    Format monitoring summary for all domains.

    Args:
        domains: List of domains with latest scan results

    Returns:
        Formatted summary
    """
    if not domains:
        return "📊 No monitoring data available"

    total = len(domains)
    enabled = sum(1 for d in domains if d.get('enabled', 1) == 1)
    disabled = total - enabled

    response = "📊 **Monitoring Summary**\n\n"
    response += f"Total Domains: **{total}**\n"
    response += f"🟢 Enabled: **{enabled}** | ⏸️ Disabled: **{disabled}**\n\n"

    # Show enabled domains
    if enabled > 0:
        response += "**Monitored Domains:**\n"
        for d in domains:
            if d.get('enabled', 1) == 1:
                response += f"  • {d.get('domain_name', 'Unknown')}\n"

    return response
