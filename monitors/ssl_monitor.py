"""
SSL Certificate Monitoring Module

Checks SSL certificate expiry for domains and alerts when certificates are close to expiration.
Uses Python standard library (ssl, socket) for certificate retrieval.
"""

import ssl
import socket
from datetime import datetime, timezone
from typing import Dict, Any
import logging
import asyncio

logger = logging.getLogger(__name__)


async def check_ssl_expiry(domain: str, port: int = 443, timeout: int = 10) -> Dict[str, Any]:
    """
    Check SSL certificate expiry for domain

    Args:
        domain: Domain name to check
        port: SSL port (default 443)
        timeout: Connection timeout in seconds (default 10)

    Returns:
        {
            "domain": str,
            "status": "ok" | "warning" | "error",
            "data": {
                "expiry_date": str (ISO format),
                "days_remaining": int,
                "issuer": str,
                "subject": str
            },
            "error": str (if status=error),
            "timestamp": str (ISO format),
            "check_duration": float
        }
    """
    start_time = datetime.now()

    try:
        # Run blocking socket operations in executor
        loop = asyncio.get_event_loop()
        cert = await loop.run_in_executor(
            None,
            _get_ssl_certificate,
            domain,
            port,
            timeout
        )

        # Parse expiry date
        not_after = cert['notAfter']
        expiry_date = datetime.strptime(
            not_after,
            '%b %d %H:%M:%S %Y %Z'
        ).replace(tzinfo=timezone.utc)

        # Calculate days remaining
        now = datetime.now(timezone.utc)
        days_remaining = (expiry_date - now).days

        # Extract issuer and subject info
        issuer = dict(x[0] for x in cert.get('issuer', []))
        subject = dict(x[0] for x in cert.get('subject', []))

        # Determine status
        if days_remaining < 0:
            status = "error"
        elif days_remaining < 7:
            status = "warning"
        else:
            status = "ok"

        check_duration = (datetime.now() - start_time).total_seconds()

        return {
            "domain": domain,
            "status": status,
            "data": {
                "expiry_date": expiry_date.isoformat(),
                "days_remaining": days_remaining,
                "issuer": issuer.get('organizationName', 'Unknown'),
                "subject": subject.get('commonName', domain)
            },
            "timestamp": datetime.now().isoformat(),
            "check_duration": check_duration
        }

    except socket.timeout:
        logger.error(f"SSL check timeout for {domain}")
        return {
            "domain": domain,
            "status": "error",
            "error": "Connection timeout",
            "timestamp": datetime.now().isoformat(),
            "check_duration": timeout
        }

    except socket.gaierror as e:
        logger.error(f"DNS resolution failed for {domain}: {e}")
        return {
            "domain": domain,
            "status": "error",
            "error": f"DNS resolution failed: {str(e)}",
            "timestamp": datetime.now().isoformat(),
            "check_duration": (datetime.now() - start_time).total_seconds()
        }

    except ssl.SSLError as e:
        logger.error(f"SSL error for {domain}: {e}")
        return {
            "domain": domain,
            "status": "error",
            "error": f"SSL error: {str(e)}",
            "timestamp": datetime.now().isoformat(),
            "check_duration": (datetime.now() - start_time).total_seconds()
        }

    except Exception as e:
        logger.error(f"Unexpected error checking SSL for {domain}: {e}")
        return {
            "domain": domain,
            "status": "error",
            "error": f"Unexpected error: {str(e)}",
            "timestamp": datetime.now().isoformat(),
            "check_duration": (datetime.now() - start_time).total_seconds()
        }


def _get_ssl_certificate(domain: str, port: int, timeout: int) -> Dict[str, Any]:
    """
    Blocking function to retrieve SSL certificate
    This is run in executor to avoid blocking the event loop
    """
    context = ssl.create_default_context()

    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            return ssock.getpeercert()


async def check_multiple_domains_ssl(domains: list[str]) -> Dict[str, Dict[str, Any]]:
    """
    Check SSL for multiple domains in parallel

    Args:
        domains: List of domain names

    Returns:
        Dictionary mapping domain names to check results
    """
    tasks = [check_ssl_expiry(domain) for domain in domains]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    return {
        domain: result if not isinstance(result, Exception) else {
            "domain": domain,
            "status": "error",
            "error": str(result),
            "timestamp": datetime.now().isoformat(),
            "check_duration": 0
        }
        for domain, result in zip(domains, results)
    }
