"""
Admin Command Handlers for CertSentinel Bot

Handles administrative commands:
- /grant_admin <user_id> - Grant admin role to user (admin only)
- /grant_viewer <user_id> - Grant viewer role to user (admin only)
- /revoke <user_id> - Revoke admin privileges (admin only)
- /list_users - List all registered users (admin only)
"""

from telegram import Update
from telegram.ext import ContextTypes
import logging

# Import dependencies
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db

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


@require_role('admin')
async def grant_admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /grant_admin <user_id> command (admin only)"""
    if not context.args:
        await update.message.reply_text(
            "⚠️ Usage: /grant_admin <user_id>\n"
            "Example: /grant_admin 123456789"
        )
        return

    try:
        target_user_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID. Must be a number.")
        return

    try:
        # Check if user exists
        role = db.get_user_role(target_user_id)
        if not role:
            await update.message.reply_text(
                f"❌ User {target_user_id} not found. They must use /start first."
            )
            return

        # Update role
        success = db.update_user_role(target_user_id, 'admin')

        if success:
            await update.message.reply_text(
                f"✅ User `{target_user_id}` granted **admin** role",
                parse_mode='Markdown'
            )
            logger.info(f"Admin {update.effective_user.id} granted admin role to {target_user_id}")
        else:
            await update.message.reply_text("❌ Failed to update role")

    except Exception as e:
        logger.error(f"Error granting admin to {target_user_id}: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")


@require_role('admin')
async def grant_viewer_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /grant_viewer <user_id> command (admin only)"""
    if not context.args:
        await update.message.reply_text(
            "⚠️ Usage: /grant_viewer <user_id>\n"
            "Example: /grant_viewer 123456789"
        )
        return

    try:
        target_user_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID. Must be a number.")
        return

    try:
        # Check if user exists
        role = db.get_user_role(target_user_id)
        if not role:
            await update.message.reply_text(
                f"❌ User {target_user_id} not found. They must use /start first."
            )
            return

        # Update role
        success = db.update_user_role(target_user_id, 'viewer')

        if success:
            await update.message.reply_text(
                f"✅ User `{target_user_id}` granted **viewer** role",
                parse_mode='Markdown'
            )
            logger.info(f"Admin {update.effective_user.id} granted viewer role to {target_user_id}")
        else:
            await update.message.reply_text("❌ Failed to update role")

    except Exception as e:
        logger.error(f"Error granting viewer to {target_user_id}: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")


@require_role('admin')
async def revoke_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /revoke <user_id> command (admin only)"""
    if not context.args:
        await update.message.reply_text(
            "⚠️ Usage: /revoke <user_id>\n"
            "Example: /revoke 123456789"
        )
        return

    try:
        target_user_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID. Must be a number.")
        return

    # Don't allow self-revocation
    if target_user_id == update.effective_user.id:
        await update.message.reply_text("❌ You cannot revoke your own access")
        return

    try:
        # Check if user exists
        role = db.get_user_role(target_user_id)
        if not role:
            await update.message.reply_text(
                f"❌ User {target_user_id} not found"
            )
            return

        # Set to viewer (minimum privilege)
        success = db.update_user_role(target_user_id, 'viewer')

        if success:
            await update.message.reply_text(
                f"✅ User `{target_user_id}` access revoked (set to viewer)",
                parse_mode='Markdown'
            )
            logger.info(f"Admin {update.effective_user.id} revoked admin from {target_user_id}")
        else:
            await update.message.reply_text("❌ Failed to revoke access")

    except Exception as e:
        logger.error(f"Error revoking access for {target_user_id}: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")


@require_role('admin')
async def list_users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /list_users command (admin only)"""
    try:
        users = db.list_users()

        if not users:
            await update.message.reply_text("📋 No users registered")
            return

        response = "👥 **Registered Users:**\n\n"
        for user in users[:20]:  # Limit to 20 users
            role_emoji = "👑" if user['role'] == 'admin' else "👤"
            username = user['username'] or 'Unknown'
            response += f"{role_emoji} `{user['user_id']}` - @{username} ({user['role']})\n"

        if len(users) > 20:
            response += f"\n... and {len(users) - 20} more users"

        await update.message.reply_text(response, parse_mode='Markdown')

    except Exception as e:
        logger.error(f"Error listing users: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")
