"""
CertSentinel Bot - Main Application
Monitors SSL certificates, uptime, and domain expiry with Telegram notifications.
"""

import asyncio
import signal
import logging
import sys
import os
from telegram.ext import Application, CommandHandler, ContextTypes
from telegram import Update

# Import all modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import db
from monitors import ssl_monitor, uptime_monitor, domain_monitor
from handlers import domain_commands, security_commands, admin_commands
from utils.config import load_config, validate_config
from utils.formatters import format_alert

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Global config and application
config = None
application = None


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle errors in the bot"""
    logger.error(f"Update {update} caused error {context.error}")

    if update and update.effective_message:
        await update.effective_message.reply_text(
            "❌ An error occurred while processing your request. Please try again."
        )


async def uptime_check_job(context: ContextTypes.DEFAULT_TYPE):
    """Background job: Check uptime for all domains"""
    logger.info("Running uptime check job...")

    try:
        domains = db.list_domains(enabled_only=True)

        for domain in domains:
            domain_id = domain['domain_id']
            domain_name = domain['domain_name']

            # Check uptime
            result = await uptime_monitor.check_uptime(f'https://{domain_name}')

            # Get previous status for state change detection
            previous_scans = db.get_recent_scans(domain_id, 'uptime', limit=1)
            previous_status = None

            if previous_scans:
                previous_status = previous_scans[0].get('result_data', {}).get('status')

            # Save new result
            db.save_scan_result(domain_id, 'uptime', result['status'], result)
            db.update_domain_check_time(domain_id, 'uptime')

            # Send alert if status changed from up to down
            if previous_status == 'up' and result['status'] in ['down', 'error']:
                await send_alert_to_all_chats(
                    context,
                    'uptime_down',
                    domain_name,
                    result.get('data', {})
                )

            # Alert on high latency (slow but not down)
            elif result['status'] == 'slow' and previous_status != 'slow':
                await send_alert_to_all_chats(
                    context,
                    'latency',
                    domain_name,
                    result.get('data', {})
                )

        logger.info(f"Uptime check completed for {len(domains)} domains")

    except Exception as e:
        logger.error(f"Error in uptime check job: {e}")


async def ssl_check_job(context: ContextTypes.DEFAULT_TYPE):
    """Background job: Check SSL certificates for all domains"""
    logger.info("Running SSL check job...")

    try:
        domains = db.list_domains(enabled_only=True)

        for domain in domains:
            domain_id = domain['domain_id']
            domain_name = domain['domain_name']

            # Check SSL
            result = await ssl_monitor.check_ssl_expiry(domain_name)

            # Get previous status for state change detection
            previous_scans = db.get_recent_scans(domain_id, 'ssl', limit=1)
            previous_warning_sent = False

            if previous_scans:
                prev_result = previous_scans[0].get('result_data', {})
                prev_days = prev_result.get('days_remaining', 999)
                previous_warning_sent = prev_days <= config.ssl_warning_days

            # Save result
            db.save_scan_result(domain_id, 'ssl', result['status'], result)
            db.update_domain_check_time(domain_id, 'ssl')

            # Send alert if expiring soon (state change: not warned -> warned)
            if result['status'] == 'warning':
                days_remaining = result.get('data', {}).get('days_remaining', 999)

                if days_remaining <= config.ssl_warning_days and not previous_warning_sent:
                    await send_alert_to_all_chats(
                        context,
                        'ssl_expiry',
                        domain_name,
                        result.get('data', {})
                    )

        logger.info(f"SSL check completed for {len(domains)} domains")

    except Exception as e:
        logger.error(f"Error in SSL check job: {e}")


async def domain_expiry_check_job(context: ContextTypes.DEFAULT_TYPE):
    """Background job: Check domain expiry for all domains"""
    logger.info("Running domain expiry check job...")

    try:
        domains = db.list_domains(enabled_only=True)

        for domain in domains:
            domain_id = domain['domain_id']
            domain_name = domain['domain_name']

            # Check domain expiry
            result = await domain_monitor.check_domain_expiry(domain_name)

            # Get previous status for state change detection
            previous_scans = db.get_recent_scans(domain_id, 'domain_expiry', limit=1)
            previous_warning_sent = False

            if previous_scans:
                prev_result = previous_scans[0].get('result_data', {})
                prev_days = prev_result.get('days_remaining', 999)
                previous_warning_sent = prev_days <= config.domain_warning_days

            # Save result
            db.save_scan_result(domain_id, 'domain_expiry', result['status'], result)
            db.update_domain_check_time(domain_id, 'domain')

            # Send alert if expiring soon (state change: not warned -> warned)
            if result['status'] == 'warning':
                days_remaining = result.get('data', {}).get('days_remaining', 999)

                if days_remaining <= config.domain_warning_days and not previous_warning_sent:
                    await send_alert_to_all_chats(
                        context,
                        'domain_expiry',
                        domain_name,
                        result.get('data', {})
                    )

            # Add delay to avoid WHOIS rate limiting
            await asyncio.sleep(2)

        logger.info(f"Domain expiry check completed for {len(domains)} domains")

    except Exception as e:
        logger.error(f"Error in domain expiry check job: {e}")


async def send_alert_to_all_chats(context: ContextTypes.DEFAULT_TYPE, alert_type: str, domain: str, details: dict):
    """
    Send alert to all registered chats

    Args:
        context: Bot context
        alert_type: Type of alert
        domain: Domain name
        details: Alert details
    """
    chats = db.get_notification_chats()

    if not chats:
        logger.warning("No chats registered for notifications")
        return

    alert_message = format_alert(alert_type, domain, details)

    for chat_id in chats:
        try:
            await context.bot.send_message(
                chat_id=chat_id,
                text=alert_message,
                parse_mode='Markdown'
            )
            logger.info(f"Alert sent to chat {chat_id} for {domain}")
        except Exception as e:
            logger.error(f"Failed to send alert to chat {chat_id}: {e}")


def register_handlers(app: Application):
    """Register all command handlers"""
    # Domain commands
    app.add_handler(CommandHandler("start", domain_commands.start_command))
    app.add_handler(CommandHandler("help", domain_commands.help_command))
    app.add_handler(CommandHandler("add", domain_commands.add_domain_command))
    app.add_handler(CommandHandler("remove", domain_commands.remove_domain_command))
    app.add_handler(CommandHandler("list", domain_commands.list_domains_command))
    app.add_handler(CommandHandler("whoami", domain_commands.whoami_command))

    # Security commands
    app.add_handler(CommandHandler("audit", security_commands.audit_command))
    app.add_handler(CommandHandler("renew", security_commands.renew_command))

    # Admin commands
    app.add_handler(CommandHandler("grant_admin", admin_commands.grant_admin_command))
    app.add_handler(CommandHandler("grant_viewer", admin_commands.grant_viewer_command))
    app.add_handler(CommandHandler("revoke", admin_commands.revoke_command))
    app.add_handler(CommandHandler("list_users", admin_commands.list_users_command))

    logger.info("All command handlers registered")


def register_jobs(app: Application):
    """Register all background jobs"""
    job_queue = app.job_queue

    # Uptime check every 5 minutes (configurable)
    job_queue.run_repeating(
        uptime_check_job,
        interval=config.uptime_check_interval,
        first=10,  # Start 10 seconds after bot starts
        name="uptime_monitor"
    )

    # SSL check every 6 hours (configurable)
    job_queue.run_repeating(
        ssl_check_job,
        interval=config.ssl_check_interval,
        first=30,
        name="ssl_monitor"
    )

    # Domain expiry check every 24 hours (configurable)
    job_queue.run_repeating(
        domain_expiry_check_job,
        interval=config.domain_check_interval,
        first=60,
        name="domain_monitor"
    )

    logger.info("All background jobs registered")


def create_application(bot_token: str) -> Application:
    """
    Create and configure the Application

    Args:
        bot_token: Telegram bot token

    Returns:
        Configured Application instance
    """
    app = Application.builder().token(bot_token).build()

    # Register command handlers
    register_handlers(app)

    # Register error handler
    app.add_error_handler(error_handler)

    logger.info("Application created and handlers registered")

    return app


def setup_initial_admin():
    """Set first admin from config if no users exist"""
    users = db.list_users()

    if not users and config.admin_ids:
        first_admin = config.admin_ids[0]
        db.add_user(first_admin, 'Initial', 'Admin', 'admin')
        logger.info(f"Initial admin user created: {first_admin}")


async def shutdown(application: Application):
    """Graceful shutdown"""
    logger.info("Shutting down bot...")

    await application.stop()
    await application.shutdown()

    logger.info("Bot shutdown complete")


async def main():
    """Main entry point"""
    global config, application

    # Load configuration
    try:
        config = load_config()
        if not validate_config(config):
            logger.error("Invalid configuration")
            return
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return

    # Configure logging level
    logging.getLogger().setLevel(config.log_level)

    # Initialize database
    try:
        db.init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return

    # Setup initial admin
    setup_initial_admin()

    # Create application
    application = create_application(config.bot_token)

    # Register background jobs
    register_jobs(application)

    # Setup signal handlers for graceful shutdown
    # SECURITY FIX: Get event loop correctly for async task creation
    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, initiating shutdown...")
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(shutdown(application))
        except RuntimeError:
            # Fallback if no running loop
            logger.warning("No running event loop, forcing shutdown")
            import sys
            sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start the bot
    logger.info("Starting CertSentinel Bot...")
    await application.initialize()
    await application.start()
    await application.updater.start_polling()

    logger.info("Bot is running. Press Ctrl+C to stop.")

    # Keep running until stopped
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Stopping bot...")
    finally:
        await shutdown(application)


if __name__ == '__main__':
    asyncio.run(main())
