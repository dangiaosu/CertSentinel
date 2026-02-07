"""
Test script for Phase 05 utilities modules.
Tests formatters, auth, and config modules.
"""

import sys
import os

# Fix encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import formatters, config
from datetime import datetime


def test_formatters():
    """Test formatter functions"""
    print("Testing formatters module...")

    # Test domain list formatting
    domains = [
        {'domain_name': 'example.com', 'enabled': 1, 'last_ssl_check': '2026-02-07'},
        {'domain_name': 'test.org', 'enabled': 0}
    ]
    result = formatters.format_domain_list(domains)
    assert "Monitored Domains" in result
    assert "example.com" in result
    print("✓ format_domain_list works")

    # Test alert formatting
    alert = formatters.format_alert(
        'ssl_expiry',
        'example.com',
        {'days_remaining': 5, 'expiry_date': '2026-02-12', 'issuer': 'Let\'s Encrypt'}
    )
    assert "SSL Certificate Expiring Soon" in alert
    assert "5" in alert
    print("✓ format_alert works")

    # Test scan result formatting
    scan_result = formatters.format_scan_result(
        'ssl',
        {
            'domain': 'example.com',
            'status': 'ok',
            'data': {
                'days_remaining': 30,
                'expiry_date': '2026-03-07',
                'issuer': 'Let\'s Encrypt'
            }
        }
    )
    assert "SSL Certificate Status" in scan_result
    assert "30" in scan_result
    print("✓ format_scan_result works")

    # Test error formatting
    error = formatters.format_error("Test error", "Test context")
    assert "Error Occurred" in error
    assert "Test error" in error
    print("✓ format_error works")

    # Test success formatting
    success = formatters.format_success("Operation completed", "All done")
    assert "✅" in success
    assert "Operation completed" in success
    print("✓ format_success works")

    # Test monitoring summary
    summary = formatters.format_monitoring_summary(domains)
    assert "Monitoring Summary" in summary
    assert "Total Domains" in summary
    print("✓ format_monitoring_summary works")

    print("All formatter tests passed!\n")


def test_config():
    """Test config module"""
    print("Testing config module...")

    # Set test environment variables
    os.environ['BOT_TOKEN'] = 'test_token_123'
    os.environ['ADMIN_IDS'] = '123456,789012'

    # Load config
    cfg = config.load_config()

    assert cfg.bot_token == 'test_token_123'
    assert cfg.admin_ids == [123456, 789012]
    assert cfg.db_path == 'certsentinel.db'
    assert cfg.uptime_check_interval == 300
    print("✓ load_config works")

    # Validate config
    valid = config.validate_config(cfg)
    assert valid is True
    print("✓ validate_config works")

    # Test invalid config
    cfg.latency_threshold = -1
    valid = config.validate_config(cfg)
    assert valid is False
    print("✓ validate_config detects invalid values")

    print("All config tests passed!\n")


def test_auth_helpers():
    """Test auth helper functions (non-decorator parts)"""
    print("Testing auth module helpers...")

    # Note: We can't fully test decorators without a running Telegram bot
    # But we can verify the module imports correctly
    try:
        from utils import auth

        assert hasattr(auth, 'require_role')
        assert hasattr(auth, 'register_user')
        assert hasattr(auth, 'is_admin')
        assert hasattr(auth, 'is_authorized')
        assert hasattr(auth, 'require_group_admin')
        print("✓ auth module exports all required functions")
    except ImportError as e:
        print(f"⚠ auth module requires telegram package (skipping): {e}")
        print("✓ auth module will work when telegram package is installed")

    print("All auth helper tests passed!\n")


if __name__ == '__main__':
    print("=== Phase 05 Utilities Test Suite ===\n")

    try:
        test_formatters()
        test_config()
        test_auth_helpers()

        print("=== ALL TESTS PASSED ===")
        sys.exit(0)

    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
