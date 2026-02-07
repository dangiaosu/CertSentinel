"""
Domain Command Handlers for CertSentinel Bot

Handles domain management commands:
- /start - Welcome message and user registration
- /help - Command help
- /add <domain> - Add domain to monitoring (admin only)
- /remove <domain> - Remove domain (admin only)
- /list - List all monitored domains
- /whoami - Show user role
"""

from telegram import Update
from telegram.ext import ContextTypes
import logging
from typing import Optional

# Import dependencies
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db
from monitors import ssl_monitor, uptime_monitor

# Import utils if available (Phase 05 parallel execution)
try:
    from utils.auth import require_role
except ImportError:
    # Fallback decorator for parallel execution
    def require_role(role: str):
        def decorator(func):
            async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
                user_id = update.effective_user.id
                user_role = db.get_user_role(user_id)

                if not user_role:
                    await update.message.reply_text("❌ You are not registered. Use /start first.")
                    return

                if role == 'admin' and user_role != 'admin':
                    await update.message.reply_text("❌ This command requires admin privileges.")
                    return

                return await func(update, context)
            return wrapper
        return decorator

logger = logging.getLogger(__name__)


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command - welcome message and user registration"""
    user = update.effective_user
    chat = update.effective_chat

    # Register user and chat
    try:
        db.add_user(user.id, user.username, user.first_name, user.last_name)
        db.register_chat(chat.id, chat.type)

        welcome_msg = (
            f"👋 Welcome to **CertSentinel Bot**, {user.first_name}!\n\n"
            "🔍 **Monitor your infrastructure:**\n"
            "• SSL certificate expiry\n"
            "• Website uptime (every 5 min)\n"
            "• Domain registration expiry\n"
            "• Security audits\n\n"
            "📝 **Commands:**\n"
            "/add <domain> - Add domain to monitor\n"
            "/remove <domain> - Remove domain\n"
            "/list - Show all monitored domains\n"
            "/audit <domain> - Run security audit\n"
            "/help - Show all commands\n"
        )

        await update.message.reply_text(welcome_msg, parse_mode='Markdown')
        logger.info(f"User {user.id} started bot")

    except Exception as e:
        logger.error(f"Error in start command: {e}")
        await update.message.reply_text("❌ Error during registration. Please try again.")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command - show all available commands"""
    help_msg = (
        "🔧 **CertSentinel Bot Commands**\n\n"
        "**Domain Management:**\n"
        "/add <domain> - Add domain to monitoring (admin)\n"
        "/remove <domain> - Remove domain (admin)\n"
        "/list - List all monitored domains\n\n"
        "**Security:**\n"
        "/audit <domain> - Run security audit\n"
        "/renew <domain> - Trigger SSL renewal (mock)\n"
        "/set_interval <domain> <type> <seconds> - Set check interval (admin)\n\n"
        "**Admin:**\n"
        "/grant_admin <user_id> - Grant admin role\n"
        "/grant_viewer <user_id> - Grant viewer role\n"
        "/revoke <user_id> - Revoke access\n"
        "/whoami - Check your role\n\n"
        "**Info:**\n"
        "/help - Show this help\n"
        "/start - Welcome message\n"
    )

    await update.message.reply_text(help_msg, parse_mode='Markdown')


@require_role('admin')
async def add_domain_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /add <domain> command (admin only)"""
    user = update.effective_user

    if not context.args:
        await update.message.reply_text(
            "⚠️ Usage: /add <domain>\n"
            "Example: /add google.com"
        )
        return

    domain = context.args[0].lower().strip()

    # Validate domain format (basic)
    if not domain or '/' in domain or ' ' in domain:
        await update.message.reply_text("❌ Invalid domain format")
        return

    try:
        # Add to database
        domain_id = db.add_domain(domain, user.id)

        if domain_id is None:
            await update.message.reply_text(
                f"⚠️ Domain **{domain}** already exists",
                parse_mode='Markdown'
            )
            return

        # Perform initial checks
        await update.message.reply_text(
            f"✅ Domain **{domain}** added! Running initial checks...",
            parse_mode='Markdown'
        )

        # Quick SSL and uptime check
        ssl_result = await ssl_monitor.check_ssl_expiry(domain)
        uptime_result = await uptime_monitor.check_uptime(f'https://{domain}')

        # Save results
        db.save_scan_result(domain_id, 'ssl', ssl_result['status'], ssl_result)
        db.save_scan_result(domain_id, 'uptime', uptime_result['status'], uptime_result)
        db.update_domain_check_time(domain_id, 'ssl')
        db.update_domain_check_time(domain_id, 'uptime')

        # Format response
        ssl_status = "✅" if ssl_result['status'] == 'ok' else "⚠️"
        uptime_status = "✅" if uptime_result['status'] == 'up' else "🔴"

        ssl_days = ssl_result.get('data', {}).get('days_remaining', 'Unknown')
        uptime_code = uptime_result.get('data', {}).get('status_code', 'Down')

        response = (
            f"📊 **Initial Check Results for {domain}:**\n\n"
            f"{ssl_status} SSL: {ssl_days} days remaining\n"
            f"{uptime_status} Uptime: {uptime_code}\n"
        )

        await update.message.reply_text(response, parse_mode='Markdown')
        logger.info(f"User {user.id} added domain: {domain}")

    except Exception as e:
        logger.error(f"Error adding domain {domain}: {e}")
        await update.message.reply_text(f"❌ Error adding domain: {str(e)}")


@require_role('admin')
async def remove_domain_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /remove <domain> command (admin only)"""
    user = update.effective_user

    if not context.args:
        await update.message.reply_text(
            "⚠️ Usage: /remove <domain>\n"
            "Example: /remove google.com"
        )
        return

    domain = context.args[0].lower().strip()

    try:
        # Remove from database
        success = db.remove_domain(domain)

        if success:
            await update.message.reply_text(
                f"✅ Domain **{domain}** removed from monitoring",
                parse_mode='Markdown'
            )
            logger.info(f"User {user.id} removed domain: {domain}")
        else:
            await update.message.reply_text(
                f"❌ Domain **{domain}** not found",
                parse_mode='Markdown'
            )

    except Exception as e:
        logger.error(f"Error removing domain {domain}: {e}")
        await update.message.reply_text(f"❌ Error removing domain: {str(e)}")


async def list_domains_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /list command (all users)"""
    try:
        domains = db.list_domains(enabled_only=True)

        if not domains:
            await update.message.reply_text("📋 No domains currently monitored")
            return

        # Get latest scan results for each domain
        domain_statuses = []
        for domain in domains:
            domain_id = domain['domain_id']
            domain_name = domain['domain_name']

            # Get latest SSL and uptime scans
            ssl_scans = db.get_recent_scans(domain_id, 'ssl', limit=1)
            uptime_scans = db.get_recent_scans(domain_id, 'uptime', limit=1)

            ssl_status = "❓"
            uptime_status = "❓"

            if ssl_scans:
                ssl_data = ssl_scans[0].get('result_data', {}).get('data', {})
                days = ssl_data.get('days_remaining', 'Unknown')
                if isinstance(days, int):
                    ssl_status = f"✅ {days}d" if days > 7 else f"⚠️ {days}d"
                else:
                    ssl_status = "❌ Error"

            if uptime_scans:
                uptime_data = uptime_scans[0].get('result_data', {})
                if uptime_data.get('status') == 'up':
                    uptime_status = "🟢 UP"
                else:
                    uptime_status = "🔴 DOWN"

            domain_statuses.append({
                'name': domain_name,
                'ssl': ssl_status,
                'uptime': uptime_status
            })

        # Format response
        response = "📋 **Monitored Domains:**\n\n"
        for d in domain_statuses:
            response += f"**{d['name']}**\n"
            response += f"  SSL: {d['ssl']} | Uptime: {d['uptime']}\n\n"

        await update.message.reply_text(response, parse_mode='Markdown')

    except Exception as e:
        logger.error(f"Error listing domains: {e}")
        await update.message.reply_text(f"❌ Error listing domains: {str(e)}")


async def whoami_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /whoami command - show user role"""
    user = update.effective_user

    try:
        role = db.get_user_role(user.id)

        if not role:
            await update.message.reply_text(
                "❌ You are not registered. Use /start to begin."
            )
            return

        role_emoji = "👑" if role == 'admin' else "👤"
        await update.message.reply_text(
            f"{role_emoji} You are: **{role.upper()}**\n"
            f"User ID: `{user.id}`",
            parse_mode='Markdown'
        )

    except Exception as e:
        logger.error(f"Error in whoami command: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")
