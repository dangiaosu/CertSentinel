"""
Security Command Handlers for CertSentinel Bot

Handles security-related commands:
- /audit <domain> - Run comprehensive security audit (all users)
- /renew <domain> - Trigger SSL certificate renewal mock (admin only)
- /set_interval <domain> <type> <seconds> - Configure check intervals (admin only)
"""

from telegram import Update
from telegram.ext import ContextTypes
import logging
import subprocess
from typing import Optional

# Import dependencies
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db
import scanner

# Import security helpers
try:
    from utils.security_audit_helpers import format_security_report
except ImportError:
    # Fallback - use inline import with corrected filename
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "security_helpers",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "utils", "security-audit-helpers.py")
    )
    security_helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(security_helpers)
    format_security_report = security_helpers.format_security_report

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


async def audit_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /audit <domain> command (all users)"""
    if not context.args:
        await update.message.reply_text(
            "⚠️ Usage: /audit <domain>\n"
            "Example: /audit google.com"
        )
        return

    domain = context.args[0].lower().strip()

    # Show processing message
    await update.message.reply_text(
        f"🔍 Running security audit for **{domain}**...",
        parse_mode='Markdown'
    )

    try:
        # Perform security audit
        audit_result = await scanner.perform_security_audit(domain)

        # Get domain_id if exists
        domain_obj = db.get_domain(domain)
        if domain_obj:
            db.save_scan_result(
                domain_obj['domain_id'],
                'security_audit',
                audit_result['score'],
                audit_result
            )

        # Format and send report
        report = format_security_report(audit_result)
        await update.message.reply_text(report, parse_mode='Markdown')

        logger.info(f"Security audit completed for {domain} by user {update.effective_user.id}")

    except Exception as e:
        logger.error(f"Error during security audit for {domain}: {e}")
        await update.message.reply_text(f"❌ Security audit failed: {str(e)}")


@require_role('admin')
async def renew_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /renew <domain> command - mock SSL renewal (admin only)"""
    if not context.args:
        await update.message.reply_text(
            "⚠️ Usage: /renew <domain>\n"
            "Example: /renew google.com"
        )
        return

    domain = context.args[0].lower().strip()

    try:
        # Check domain exists
        domain_obj = db.get_domain(domain)
        if not domain_obj:
            await update.message.reply_text(
                f"❌ Domain **{domain}** not found in monitoring list",
                parse_mode='Markdown'
            )
            return

        await update.message.reply_text(
            f"🔄 Initiating SSL renewal for **{domain}**...",
            parse_mode='Markdown'
        )

        # Mock certbot command (for demonstration)
        # In production, this would run: certbot renew --force-renewal --cert-name domain
        # SECURITY: Use list instead of shell=True to prevent command injection
        result = subprocess.run(
            ['echo', f"Mock certbot renew for {domain}"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            output = result.stdout or "Renewal simulated successfully"
            await update.message.reply_text(
                f"✅ **SSL Renewal Output:**\n```\n{output[:500]}\n```",
                parse_mode='Markdown'
            )
            logger.info(f"SSL renewal triggered for {domain} by user {update.effective_user.id}")
        else:
            error = result.stderr or "Unknown error"
            await update.message.reply_text(
                f"❌ Renewal failed:\n```\n{error[:500]}\n```",
                parse_mode='Markdown'
            )

    except subprocess.TimeoutExpired:
        await update.message.reply_text("❌ Renewal command timeout")
    except Exception as e:
        logger.error(f"Error during renewal for {domain}: {e}")
        await update.message.reply_text(f"❌ Renewal failed: {str(e)}")


@require_role('admin')
async def set_interval_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /set_interval <domain> <type> <seconds> command (admin only)"""
    if len(context.args) < 3:
        await update.message.reply_text(
            "⚠️ Usage: /set_interval <domain> <type> <seconds>\n\n"
            "Types: ssl, uptime, domain\n"
            "Example: /set_interval google.com ssl 3600"
        )
        return

    domain = context.args[0].lower().strip()
    check_type = context.args[1].lower().strip()

    try:
        interval = int(context.args[2])
    except ValueError:
        await update.message.reply_text("❌ Interval must be a number (seconds)")
        return

    # Validate check type
    valid_types = ['ssl', 'uptime', 'domain']
    if check_type not in valid_types:
        await update.message.reply_text(
            f"❌ Invalid check type. Use: {', '.join(valid_types)}"
        )
        return

    # Validate interval range (min 60s, max 7 days)
    if interval < 60 or interval > 604800:
        await update.message.reply_text(
            "❌ Interval must be between 60 seconds (1 min) and 604800 seconds (7 days)"
        )
        return

    try:
        # Get domain
        domain_obj = db.get_domain(domain)
        if not domain_obj:
            await update.message.reply_text(
                f"❌ Domain **{domain}** not found",
                parse_mode='Markdown'
            )
            return

        domain_id = domain_obj['domain_id']

        # Update interval based on type
        if check_type == 'ssl':
            db.update_domain_preferences(domain_id, ssl_interval=interval)
        elif check_type == 'uptime':
            db.update_domain_preferences(domain_id, uptime_interval=interval)
        elif check_type == 'domain':
            db.update_domain_preferences(domain_id, domain_interval=interval)

        # Format interval for display
        if interval >= 86400:
            interval_str = f"{interval // 86400} day(s)"
        elif interval >= 3600:
            interval_str = f"{interval // 3600} hour(s)"
        elif interval >= 60:
            interval_str = f"{interval // 60} minute(s)"
        else:
            interval_str = f"{interval} second(s)"

        await update.message.reply_text(
            f"✅ **{check_type.upper()}** check interval for **{domain}** set to **{interval_str}**",
            parse_mode='Markdown'
        )
        logger.info(f"User {update.effective_user.id} set {check_type} interval to {interval}s for {domain}")

    except Exception as e:
        logger.error(f"Error setting interval for {domain}: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")
