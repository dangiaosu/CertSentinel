"""
Database module for CertSentinel bot.
Handles SQLite operations for users, domains, scan results, notifications, and chat configs.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, List, Dict, Any
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_PATH = 'certsentinel.db'


@contextmanager
def get_db_connection(db_path: str = DB_PATH):
    """Context manager for safe DB connections with automatic commit/rollback"""
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Initialize database with all tables"""
    with get_db_connection() as conn:
        # Users table with RBAC
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                role TEXT NOT NULL CHECK(role IN ('admin', 'viewer')) DEFAULT 'viewer',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP
            )
        """)

        # Domains to monitor
        conn.execute("""
            CREATE TABLE IF NOT EXISTS domains (
                domain_id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_name TEXT UNIQUE NOT NULL,
                added_by INTEGER REFERENCES users(user_id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                enabled BOOLEAN DEFAULT 1,
                last_ssl_check TIMESTAMP,
                last_uptime_check TIMESTAMP,
                last_domain_check TIMESTAMP
            )
        """)

        # Scan results
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER REFERENCES domains(domain_id) ON DELETE CASCADE,
                scan_type TEXT NOT NULL,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL,
                result_json TEXT,
                notes TEXT
            )
        """)

        # Notifications log
        conn.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(user_id),
                scan_id INTEGER REFERENCES scan_results(scan_id),
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notification_type TEXT,
                delivered BOOLEAN DEFAULT 1
            )
        """)

        # Chat configurations
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_configs (
                chat_id INTEGER PRIMARY KEY,
                chat_type TEXT NOT NULL,
                notification_enabled BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # User preferences
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_preferences (
                user_id INTEGER PRIMARY KEY REFERENCES users(user_id),
                notify_expiry BOOLEAN DEFAULT 1,
                notify_security_issues BOOLEAN DEFAULT 1,
                notification_days_before INTEGER DEFAULT 7,
                timezone TEXT DEFAULT 'UTC'
            )
        """)

        # Domain preferences - per-domain check intervals
        conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_preferences (
                domain_id INTEGER PRIMARY KEY REFERENCES domains(domain_id) ON DELETE CASCADE,
                ssl_check_interval INTEGER DEFAULT 86400,
                uptime_check_interval INTEGER DEFAULT 300,
                domain_check_interval INTEGER DEFAULT 86400
            )
        """)

        # Create indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_enabled ON domains(enabled)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_domain ON scan_results(domain_id, scan_date)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, sent_at)")

    logger.info("Database initialized successfully")


# User operations
def add_user(user_id: int, username: str, first_name: str, last_name: str, role: str = 'viewer') -> bool:
    """Add or update user in database"""
    try:
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO users (user_id, username, first_name, last_name, role, last_active)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    username = excluded.username,
                    first_name = excluded.first_name,
                    last_name = excluded.last_name,
                    last_active = excluded.last_active
            """, (user_id, username, first_name, last_name, role, datetime.now()))
        logger.info(f"User added/updated: {username} (ID: {user_id})")
        return True
    except Exception as e:
        logger.error(f"Error adding user {user_id}: {e}")
        raise


def get_user_role(user_id: int) -> Optional[str]:
    """Get user role from database"""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT role FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            return row['role'] if row else None
    except Exception as e:
        logger.error(f"Error getting user role for {user_id}: {e}")
        raise


def update_user_role(user_id: int, new_role: str) -> bool:
    """Update user role (admin/viewer)"""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                "UPDATE users SET role = ? WHERE user_id = ?",
                (new_role, user_id)
            )
            success = cursor.rowcount > 0
            if success:
                logger.info(f"User {user_id} role updated to {new_role}")
            return success
    except Exception as e:
        logger.error(f"Error updating user role for {user_id}: {e}")
        raise


def list_users() -> List[Dict[str, Any]]:
    """List all users with their roles"""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute("""
                SELECT user_id, username, first_name, last_name, role, created_at, last_active
                FROM users ORDER BY created_at DESC
            """)
            return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise


# Domain operations
def add_domain(domain_name: str, added_by: int) -> Optional[int]:
    """Add domain to monitoring list"""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                "INSERT INTO domains (domain_name, added_by) VALUES (?, ?)",
                (domain_name.lower().strip(), added_by)
            )
            domain_id = cursor.lastrowid
            # Initialize domain preferences with defaults
            conn.execute(
                "INSERT INTO domain_preferences (domain_id) VALUES (?)",
                (domain_id,)
            )
            logger.info(f"Domain added: {domain_name} by user {added_by}")
            return domain_id
    except sqlite3.IntegrityError:
        logger.warning(f"Domain already exists: {domain_name}")
        return None
    except Exception as e:
        logger.error(f"Error adding domain {domain_name}: {e}")
        raise


def remove_domain(domain_name: str) -> bool:
    """Remove domain from monitoring"""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM domains WHERE domain_name = ?",
                (domain_name.lower().strip(),)
            )
            success = cursor.rowcount > 0
            if success:
                logger.info(f"Domain removed: {domain_name}")
            return success
    except Exception as e:
        logger.error(f"Error removing domain {domain_name}: {e}")
        raise


def list_domains(enabled_only: bool = True) -> List[Dict[str, Any]]:
    """List all monitored domains"""
    try:
        with get_db_connection() as conn:
            query = """
                SELECT d.domain_id, d.domain_name, d.added_by, d.created_at, d.enabled,
                       d.last_ssl_check, d.last_uptime_check, d.last_domain_check,
                       u.username as added_by_username
                FROM domains d
                LEFT JOIN users u ON d.added_by = u.user_id
            """
            if enabled_only:
                query += " WHERE d.enabled = 1"
            query += " ORDER BY d.created_at DESC"

            cursor = conn.execute(query)
            return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error listing domains: {e}")
        raise


def get_domain(domain_name: str) -> Optional[Dict[str, Any]]:
    """Get single domain details"""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM domains WHERE domain_name = ?",
                (domain_name.lower().strip(),)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error getting domain {domain_name}: {e}")
        raise


def update_domain_check_time(domain_id: int, check_type: str):
    """Update last check timestamp for domain"""
    column_map = {
        'ssl': 'last_ssl_check',
        'uptime': 'last_uptime_check',
        'domain': 'last_domain_check'
    }
    column = column_map.get(check_type)
    if not column:
        logger.warning(f"Invalid check type: {check_type}")
        return

    try:
        with get_db_connection() as conn:
            conn.execute(
                f"UPDATE domains SET {column} = ? WHERE domain_id = ?",
                (datetime.now(), domain_id)
            )
    except Exception as e:
        logger.error(f"Error updating check time for domain {domain_id}: {e}")
        raise


def get_domain_preferences(domain_id: int) -> Optional[Dict[str, Any]]:
    """Get check interval preferences for a domain"""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM domain_preferences WHERE domain_id = ?",
                (domain_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error getting domain preferences for {domain_id}: {e}")
        raise


def update_domain_preferences(domain_id: int, ssl_interval: int = None,
                             uptime_interval: int = None, domain_interval: int = None) -> bool:
    """Update check interval preferences for a domain"""
    try:
        updates = []
        params = []
        if ssl_interval is not None:
            updates.append("ssl_check_interval = ?")
            params.append(ssl_interval)
        if uptime_interval is not None:
            updates.append("uptime_check_interval = ?")
            params.append(uptime_interval)
        if domain_interval is not None:
            updates.append("domain_check_interval = ?")
            params.append(domain_interval)

        if not updates:
            return False

        params.append(domain_id)
        with get_db_connection() as conn:
            cursor = conn.execute(
                f"UPDATE domain_preferences SET {', '.join(updates)} WHERE domain_id = ?",
                params
            )
            return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Error updating domain preferences for {domain_id}: {e}")
        raise


# Scan operations
def save_scan_result(domain_id: int, scan_type: str, status: str,
                    result_data: Dict[str, Any], notes: str = None) -> int:
    """Save scan result to database"""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO scan_results (domain_id, scan_type, status, result_json, notes)
                VALUES (?, ?, ?, ?, ?)
            """, (domain_id, scan_type, status, json.dumps(result_data), notes))
            scan_id = cursor.lastrowid
            logger.info(f"Scan result saved: {scan_type} for domain {domain_id}, status: {status}")
            return scan_id
    except Exception as e:
        logger.error(f"Error saving scan result for domain {domain_id}: {e}")
        raise


def get_recent_scans(domain_id: int, scan_type: str = None, limit: int = 10) -> List[Dict[str, Any]]:
    """Get recent scan results for domain"""
    try:
        with get_db_connection() as conn:
            query = "SELECT * FROM scan_results WHERE domain_id = ?"
            params = [domain_id]

            if scan_type:
                query += " AND scan_type = ?"
                params.append(scan_type)

            query += " ORDER BY scan_date DESC LIMIT ?"
            params.append(limit)

            cursor = conn.execute(query, params)
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                if result['result_json']:
                    result['result_data'] = json.loads(result['result_json'])
                results.append(result)
            return results
    except Exception as e:
        logger.error(f"Error getting recent scans for domain {domain_id}: {e}")
        raise


# Notification operations
def log_notification(user_id: int, scan_id: int, notification_type: str) -> int:
    """Log sent notification"""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO notifications (user_id, scan_id, notification_type)
                VALUES (?, ?, ?)
            """, (user_id, scan_id, notification_type))
            logger.info(f"Notification logged: type={notification_type} for user {user_id}")
            return cursor.lastrowid
    except Exception as e:
        logger.error(f"Error logging notification for user {user_id}: {e}")
        raise


def get_notification_history(user_id: int = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Get notification history, optionally filtered by user"""
    try:
        with get_db_connection() as conn:
            if user_id:
                cursor = conn.execute("""
                    SELECT * FROM notifications WHERE user_id = ?
                    ORDER BY sent_at DESC LIMIT ?
                """, (user_id, limit))
            else:
                cursor = conn.execute("""
                    SELECT * FROM notifications ORDER BY sent_at DESC LIMIT ?
                """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error getting notification history: {e}")
        raise


# Chat operations
def register_chat(chat_id: int, chat_type: str) -> bool:
    """Register chat for notifications"""
    try:
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO chat_configs (chat_id, chat_type)
                VALUES (?, ?)
                ON CONFLICT(chat_id) DO UPDATE SET chat_type = excluded.chat_type
            """, (chat_id, chat_type))
        logger.info(f"Chat registered: {chat_id} ({chat_type})")
        return True
    except Exception as e:
        logger.error(f"Error registering chat {chat_id}: {e}")
        raise


def update_chat_config(chat_id: int, notification_enabled: bool) -> bool:
    """Update chat notification settings"""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                "UPDATE chat_configs SET notification_enabled = ? WHERE chat_id = ?",
                (notification_enabled, chat_id)
            )
            return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Error updating chat config for {chat_id}: {e}")
        raise


def get_notification_chats() -> List[int]:
    """Get all chat IDs that should receive notifications"""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                "SELECT chat_id FROM chat_configs WHERE notification_enabled = 1"
            )
            return [row['chat_id'] for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error getting notification chats: {e}")
        raise


# User preferences operations
def set_user_preferences(user_id: int, notify_expiry: bool = None,
                        notify_security: bool = None, days_before: int = None,
                        timezone: str = None) -> bool:
    """Set user notification preferences"""
    try:
        with get_db_connection() as conn:
            # Insert or update preferences
            updates = []
            params = []
            if notify_expiry is not None:
                updates.append("notify_expiry = ?")
                params.append(notify_expiry)
            if notify_security is not None:
                updates.append("notify_security_issues = ?")
                params.append(notify_security)
            if days_before is not None:
                updates.append("notification_days_before = ?")
                params.append(days_before)
            if timezone is not None:
                updates.append("timezone = ?")
                params.append(timezone)

            if not updates:
                return False

            params.append(user_id)
            conn.execute(f"""
                INSERT INTO user_preferences (user_id) VALUES (?)
                ON CONFLICT(user_id) DO UPDATE SET {', '.join(updates)}
            """, [user_id] + params[:-1])
            return True
    except Exception as e:
        logger.error(f"Error setting user preferences for {user_id}: {e}")
        raise


def get_user_preferences(user_id: int) -> Optional[Dict[str, Any]]:
    """Get user notification preferences"""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM user_preferences WHERE user_id = ?",
                (user_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error getting user preferences for {user_id}: {e}")
        raise


if __name__ == '__main__':
    init_db()
    logger.info("Database initialized via direct execution")
