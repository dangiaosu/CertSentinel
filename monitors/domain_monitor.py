"""
Domain Expiry Monitoring Module

Checks domain registration expiry using WHOIS lookups.
Alerts when domains are close to expiration (<30 days).
"""

import whois
import asyncio
from datetime import datetime
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


async def check_domain_expiry(domain: str) -> Dict[str, Any]:
    """
    Check domain registration expiry using WHOIS

    Note: python-whois is blocking, so we run it in executor

    Args:
        domain: Domain name to check

    Returns:
        {
            "domain": str,
            "status": "ok" | "warning" | "error",
            "data": {
                "expiry_date": str (ISO format),
                "days_remaining": int,
                "registrar": str,
                "creation_date": str (ISO format)
            },
            "error": str (if applicable),
            "timestamp": str (ISO format),
            "check_duration": float
        }
    """
    start_time = datetime.now()

    try:
        # Run blocking WHOIS call in executor
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)

        # Handle expiration_date (can be single date or list)
        expiry_date = w.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]

        if not expiry_date:
            return {
                "domain": domain,
                "status": "error",
                "error": "No expiry date found in WHOIS data",
                "timestamp": datetime.now().isoformat(),
                "check_duration": (datetime.now() - start_time).total_seconds()
            }

        # Calculate days remaining
        # Handle both timezone-aware and timezone-naive datetimes
        now = datetime.now()

        # Normalize both datetimes to timezone-naive
        if expiry_date.tzinfo is not None:
            expiry_date = expiry_date.replace(tzinfo=None)
        if now.tzinfo is not None:
            now = now.replace(tzinfo=None)

        days_remaining = (expiry_date - now).days

        # Determine status
        if days_remaining < 0:
            status = "error"
        elif days_remaining < 30:
            status = "warning"
        else:
            status = "ok"

        # Handle creation_date (can be single date or list)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        check_duration = (datetime.now() - start_time).total_seconds()

        return {
            "domain": domain,
            "status": status,
            "data": {
                "expiry_date": expiry_date.isoformat() if expiry_date else None,
                "days_remaining": days_remaining,
                "registrar": w.registrar or "Unknown",
                "creation_date": creation_date.isoformat() if creation_date else None
            },
            "timestamp": datetime.now().isoformat(),
            "check_duration": check_duration
        }

    except Exception as e:
        logger.error(f"WHOIS error for {domain}: {e}")
        return {
            "domain": domain,
            "status": "error",
            "error": f"WHOIS lookup failed: {str(e)}",
            "timestamp": datetime.now().isoformat(),
            "check_duration": (datetime.now() - start_time).total_seconds()
        }


async def check_multiple_domains_expiry(domains: list[str]) -> Dict[str, Dict[str, Any]]:
    """
    Check domain expiry for multiple domains

    Note: Add delays between checks to avoid WHOIS rate limiting

    Args:
        domains: List of domain names

    Returns:
        Dictionary mapping domain names to check results
    """
    results = {}

    for i, domain in enumerate(domains):
        result = await check_domain_expiry(domain)
        results[domain] = result

        # Add delay between checks to avoid rate limiting (except last one)
        if i < len(domains) - 1:
            await asyncio.sleep(2)  # 2 second delay

    return results
