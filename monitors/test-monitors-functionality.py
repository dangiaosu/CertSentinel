"""
Test script for monitoring modules

Tests SSL, uptime, and domain monitoring functionality with real examples.
Run with: python -m CertSentinel.monitors.test-monitors-functionality
"""

import asyncio
import logging
from ssl_monitor import check_ssl_expiry, check_multiple_domains_ssl
from uptime_monitor import check_uptime, check_multiple_urls_uptime
from domain_monitor import check_domain_expiry, check_multiple_domains_expiry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


async def test_ssl_monitor():
    """Test SSL certificate monitoring"""
    print("\n" + "="*60)
    print("Testing SSL Certificate Monitor")
    print("="*60)

    # Test single domain
    print("\n1. Single domain check (google.com):")
    result = await check_ssl_expiry("google.com")
    print(f"   Status: {result['status']}")
    print(f"   Days remaining: {result.get('data', {}).get('days_remaining', 'N/A')}")
    print(f"   Check duration: {result['check_duration']:.3f}s")

    # Test multiple domains in parallel
    print("\n2. Multiple domains check (parallel):")
    domains = ["google.com", "github.com", "cloudflare.com"]
    results = await check_multiple_domains_ssl(domains)
    for domain, result in results.items():
        status = result['status']
        days = result.get('data', {}).get('days_remaining', 'N/A')
        print(f"   {domain}: {status} ({days} days)")

    # Test invalid domain
    print("\n3. Invalid domain check (should fail gracefully):")
    result = await check_ssl_expiry("invalid-domain-that-does-not-exist.com")
    print(f"   Status: {result['status']}")
    print(f"   Error: {result.get('error', 'N/A')}")


async def test_uptime_monitor():
    """Test uptime monitoring"""
    print("\n" + "="*60)
    print("Testing Uptime Monitor")
    print("="*60)

    # Test single URL
    print("\n1. Single URL check (https://google.com):")
    result = await check_uptime("https://google.com")
    print(f"   Status: {result['status']}")
    print(f"   HTTP status: {result.get('data', {}).get('status_code', 'N/A')}")
    print(f"   Response time: {result.get('data', {}).get('response_time', 'N/A')}s")

    # Test multiple URLs in parallel
    print("\n2. Multiple URLs check (parallel):")
    urls = [
        "https://google.com",
        "https://github.com",
        "https://cloudflare.com"
    ]
    results = await check_multiple_urls_uptime(urls)
    for url, result in results.items():
        status = result['status']
        http_status = result.get('data', {}).get('status_code', 'N/A')
        response_time = result.get('data', {}).get('response_time', 'N/A')
        print(f"   {url}: {status} (HTTP {http_status}, {response_time}s)")

    # Test URL without scheme
    print("\n3. URL without scheme (should add https://):")
    result = await check_uptime("github.com")
    print(f"   URL: {result['url']}")
    print(f"   Status: {result['status']}")

    # Test invalid URL
    print("\n4. Invalid URL check (should fail gracefully):")
    result = await check_uptime("https://invalid-domain-xyz123.com")
    print(f"   Status: {result['status']}")
    print(f"   Error: {result.get('error', 'N/A')}")


async def test_domain_monitor():
    """Test domain expiry monitoring"""
    print("\n" + "="*60)
    print("Testing Domain Expiry Monitor")
    print("="*60)

    # Test single domain
    print("\n1. Single domain check (google.com):")
    print("   (This may take a few seconds for WHOIS lookup...)")
    result = await check_domain_expiry("google.com")
    print(f"   Status: {result['status']}")
    print(f"   Days remaining: {result.get('data', {}).get('days_remaining', 'N/A')}")
    print(f"   Registrar: {result.get('data', {}).get('registrar', 'N/A')}")
    print(f"   Check duration: {result['check_duration']:.3f}s")

    # Test multiple domains with rate limiting
    print("\n2. Multiple domains check (with 2s delay for rate limiting):")
    domains = ["google.com", "github.com"]
    print("   (This will take ~4+ seconds due to rate limiting...)")
    results = await check_multiple_domains_expiry(domains)
    for domain, result in results.items():
        status = result['status']
        days = result.get('data', {}).get('days_remaining', 'N/A')
        print(f"   {domain}: {status} ({days} days)")

    # Test invalid domain
    print("\n3. Invalid domain check (should fail gracefully):")
    result = await check_domain_expiry("invalid-domain-xyz123.com")
    print(f"   Status: {result['status']}")
    print(f"   Error: {result.get('error', 'N/A')}")


async def main():
    """Run all tests"""
    print("\n")
    print("╔" + "═"*58 + "╗")
    print("║" + " "*15 + "CertSentinel Monitor Tests" + " "*17 + "║")
    print("╚" + "═"*58 + "╝")

    try:
        # Run all monitor tests
        await test_ssl_monitor()
        await test_uptime_monitor()
        await test_domain_monitor()

        print("\n" + "="*60)
        print("All tests completed!")
        print("="*60 + "\n")

    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    asyncio.run(main())
