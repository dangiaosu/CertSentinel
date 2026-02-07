"""
RBAC decorators and authentication utilities for CertSentinel bot.
Handles role-based access control with admin/viewer permissions.
"""

from telegram import Update
from telegram.ext import ContextTypes
from functools import wraps
import sys
import os

# Add parent directory to path to import db module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db

import logging

logger = logging.getLogger(__name__)


def require_role(role: str):
    """
    Decorator to require specific role for command execution.

    Args:
        role: Required role ('admin' or 'viewer')

    Usage:
        @require_role('admin')
        async def admin_command(update, context):
            pass
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
            user = update.effective_user

            # Auto-register user if not exists
            db.add_user(user.id, user.username, user.first_name, user.last_name)

            # Get user role
            user_role = db.get_user_role(user.id)

            if user_role is None:
                await update.message.reply_text(
                    "⛔ **Access Denied**\n\n"
                    "You are not authorized. Please use /start to register.",
                    parse_mode='Markdown'
                )
                logger.warning(f"Unauthorized access attempt by user {user.id} ({user.username})")
                return

            # Check role requirement
            if role == 'admin' and user_role != 'admin':
                await update.message.reply_text(
                    "⛔ **Admin Access Required**\n\n"
                    "This command is only available to administrators.",
                    parse_mode='Markdown'
                )
                logger.warning(f"User {user.id} ({user_role}) attempted admin-only command: {func.__name__}")
                return

            # Execute command
            return await func(update, context, *args, **kwargs)

        return wrapper
    return decorator


def register_user(func):
    """
    Decorator to auto-register user on command.

    Usage:
        @register_user
        async def some_command(update, context):
            pass
    """
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user = update.effective_user
        chat = update.effective_chat

        # Register user if not exists
        db.add_user(user.id, user.username, user.first_name, user.last_name)

        # Register chat if not exists
        db.register_chat(chat.id, chat.type)

        # Update last active
        db.add_user(user.id, user.username, user.first_name, user.last_name)

        return await func(update, context, *args, **kwargs)

    return wrapper


async def is_admin(user_id: int) -> bool:
    """
    Check if user is admin.

    Args:
        user_id: Telegram user ID

    Returns:
        True if admin, False otherwise
    """
    role = db.get_user_role(user_id)
    return role == 'admin'


async def is_authorized(user_id: int) -> bool:
    """
    Check if user has any access (admin or viewer).

    Args:
        user_id: Telegram user ID

    Returns:
        True if authorized, False otherwise
    """
    role = db.get_user_role(user_id)
    return role is not None


def require_group_admin(func):
    """
    Decorator to require group admin status (for group chats).

    Usage:
        @require_group_admin
        async def group_command(update, context):
            pass
    """
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        chat = update.effective_chat
        user = update.effective_user

        # Only apply to group chats
        if chat.type in ['group', 'supergroup']:
            try:
                member = await context.bot.get_chat_member(chat.id, user.id)

                if member.status not in ['creator', 'administrator']:
                    await update.message.reply_text(
                        "⛔ **Group Admin Required**\n\n"
                        "This command can only be used by group administrators.",
                        parse_mode='Markdown'
                    )
                    return

            except Exception as e:
                logger.error(f"Error checking group admin status: {e}")
                await update.message.reply_text("❌ Could not verify admin status")
                return

        return await func(update, context, *args, **kwargs)

    return wrapper
