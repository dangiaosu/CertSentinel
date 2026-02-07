"""
Uptime Monitoring Module

Checks website availability and response time using async HTTP requests.
Alerts when sites are down (status != 200) or slow (response time > 2s).
"""

import aiohttp
import asyncio
from datetime import datetime
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


async def check_uptime(
    url: str,
    timeout: int = 10,
    expected_status: int = 200
) -> Dict[str, Any]:
    """
    Check website uptime and response time

    Args:
        url: URL to check (scheme optional, defaults to https)
        timeout: Request timeout in seconds (default 10)
        expected_status: Expected HTTP status code (default 200)

    Returns:
        {
            "url": str,
            "status": "up" | "down" | "slow" | "error",
            "data": {
                "status_code": int,
                "response_time": float,  # seconds
                "content_length": int
            },
            "error": str (if applicable),
            "timestamp": str (ISO format),
            "check_duration": float
        }
    """
    start_time = datetime.now()

    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True
            ) as response:
                response_time = (datetime.now() - start_time).total_seconds()
                content_length = response.content_length or 0

                # Determine status
                if response.status >= 500:
                    status = "down"
                elif response.status != expected_status:
                    status = "down"
                elif response_time > 2.0:
                    status = "slow"
                else:
                    status = "up"

                return {
                    "url": url,
                    "status": status,
                    "data": {
                        "status_code": response.status,
                        "response_time": round(response_time, 3),
                        "content_length": content_length
                    },
                    "timestamp": datetime.now().isoformat(),
                    "check_duration": response_time
                }

    except asyncio.TimeoutError:
        logger.error(f"Uptime check timeout for {url}")
        return {
            "url": url,
            "status": "down",
            "error": "Request timeout",
            "timestamp": datetime.now().isoformat(),
            "check_duration": timeout
        }

    except aiohttp.ClientConnectorError as e:
        logger.error(f"Connection error for {url}: {e}")
        return {
            "url": url,
            "status": "down",
            "error": f"Connection failed: {str(e)}",
            "timestamp": datetime.now().isoformat(),
            "check_duration": (datetime.now() - start_time).total_seconds()
        }

    except aiohttp.ClientError as e:
        logger.error(f"HTTP client error for {url}: {e}")
        return {
            "url": url,
            "status": "error",
            "error": f"HTTP error: {str(e)}",
            "timestamp": datetime.now().isoformat(),
            "check_duration": (datetime.now() - start_time).total_seconds()
        }

    except Exception as e:
        logger.error(f"Unexpected error checking uptime for {url}: {e}")
        return {
            "url": url,
            "status": "error",
            "error": f"Unexpected error: {str(e)}",
            "timestamp": datetime.now().isoformat(),
            "check_duration": (datetime.now() - start_time).total_seconds()
        }


async def check_multiple_urls_uptime(urls: list[str]) -> Dict[str, Dict[str, Any]]:
    """
    Check uptime for multiple URLs in parallel

    Args:
        urls: List of URLs to check

    Returns:
        Dictionary mapping URLs to check results
    """
    tasks = [check_uptime(url) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    return {
        url: result if not isinstance(result, Exception) else {
            "url": url,
            "status": "error",
            "error": str(result),
            "timestamp": datetime.now().isoformat(),
            "check_duration": 0
        }
        for url, result in zip(urls, results)
    }
