"""
Configuration management for CertSentinel bot.
Handles loading and validation of environment variables.
"""

import os
from typing import Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Application configuration"""
    # Bot configuration
    bot_token: str
    admin_ids: list[int]

    # Database
    db_path: str = 'certsentinel.db'

    # Monitoring intervals (seconds)
    uptime_check_interval: int = 300  # 5 minutes
    ssl_check_interval: int = 21600  # 6 hours
    domain_check_interval: int = 86400  # 24 hours

    # Alert thresholds
    ssl_warning_days: int = 7
    domain_warning_days: int = 30
    latency_threshold: float = 2.0  # seconds

    # Scan timeouts (seconds)
    ssl_timeout: int = 10
    uptime_timeout: int = 10
    domain_timeout: int = 30
    port_scan_timeout: int = 2

    # Notification settings
    enable_notifications: bool = True
    notification_quiet_hours: tuple = None  # (start_hour, end_hour) or None

    # Logging
    log_level: str = 'INFO'
    log_file: str = 'certsentinel.log'


def load_config() -> Config:
    """
    Load configuration from environment variables.

    Required:
        BOT_TOKEN: Telegram bot token
        ADMIN_IDS: Comma-separated list of admin user IDs

    Optional:
        DB_PATH: Database file path
        UPTIME_INTERVAL: Uptime check interval in seconds
        SSL_INTERVAL: SSL check interval in seconds
        DOMAIN_INTERVAL: Domain check interval in seconds
        SSL_WARNING_DAYS: SSL warning threshold in days
        DOMAIN_WARNING_DAYS: Domain warning threshold in days
        LATENCY_THRESHOLD: Latency threshold in seconds
        LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)

    Returns:
        Config object

    Raises:
        ValueError: If required environment variables are missing
    """
    # Required variables
    bot_token = os.getenv('BOT_TOKEN')
    if not bot_token:
        raise ValueError("BOT_TOKEN environment variable is required")

    admin_ids_str = os.getenv('ADMIN_IDS', '')
    if not admin_ids_str:
        raise ValueError("ADMIN_IDS environment variable is required (comma-separated user IDs)")

    try:
        admin_ids = [int(id.strip()) for id in admin_ids_str.split(',') if id.strip()]
    except ValueError:
        raise ValueError("ADMIN_IDS must be comma-separated integers")

    if not admin_ids:
        raise ValueError("ADMIN_IDS must contain at least one admin user ID")

    # Optional variables with defaults
    config = Config(
        bot_token=bot_token,
        admin_ids=admin_ids,
        db_path=os.getenv('DB_PATH', 'certsentinel.db'),
        uptime_check_interval=int(os.getenv('UPTIME_INTERVAL', '300')),
        ssl_check_interval=int(os.getenv('SSL_INTERVAL', '21600')),
        domain_check_interval=int(os.getenv('DOMAIN_INTERVAL', '86400')),
        ssl_warning_days=int(os.getenv('SSL_WARNING_DAYS', '7')),
        domain_warning_days=int(os.getenv('DOMAIN_WARNING_DAYS', '30')),
        latency_threshold=float(os.getenv('LATENCY_THRESHOLD', '2.0')),
        ssl_timeout=int(os.getenv('SSL_TIMEOUT', '10')),
        uptime_timeout=int(os.getenv('UPTIME_TIMEOUT', '10')),
        domain_timeout=int(os.getenv('DOMAIN_TIMEOUT', '30')),
        port_scan_timeout=int(os.getenv('PORT_SCAN_TIMEOUT', '2')),
        enable_notifications=os.getenv('ENABLE_NOTIFICATIONS', 'true').lower() == 'true',
        log_level=os.getenv('LOG_LEVEL', 'INFO'),
        log_file=os.getenv('LOG_FILE', 'certsentinel.log')
    )

    logger.info(f"Configuration loaded: {len(admin_ids)} admins, DB: {config.db_path}")

    return config


def validate_config(config: Config) -> bool:
    """
    Validate configuration values.

    Args:
        config: Config object

    Returns:
        True if valid, False otherwise
    """
    # Check intervals are positive
    if config.uptime_check_interval <= 0:
        logger.error("uptime_check_interval must be positive")
        return False

    if config.ssl_check_interval <= 0:
        logger.error("ssl_check_interval must be positive")
        return False

    if config.domain_check_interval <= 0:
        logger.error("domain_check_interval must be positive")
        return False

    # Check thresholds are reasonable
    if config.ssl_warning_days < 1 or config.ssl_warning_days > 90:
        logger.warning(f"ssl_warning_days ({config.ssl_warning_days}) should be between 1-90 days")

    if config.latency_threshold <= 0:
        logger.error("latency_threshold must be positive")
        return False

    # Check log level is valid
    valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    if config.log_level.upper() not in valid_log_levels:
        logger.error(f"Invalid log level: {config.log_level}")
        return False

    logger.info("Configuration validation passed")
    return True
