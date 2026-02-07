"""
CertSentinel Bot Command Handlers

This package contains all command handlers for the Telegram bot:
- domain-commands.py: Domain management (/add, /remove, /list, /whoami)
- security-commands.py: Security operations (/audit, /renew, /set_interval)
- admin-commands.py: Admin functions (/grant_admin, /grant_viewer, /revoke, /list_users)
"""

# Import all command handlers for easy access
# Note: Using importlib due to kebab-case filenames
import importlib.util
import os

def _load_module(module_name, file_name):
    """Load module from kebab-case filename"""
    spec = importlib.util.spec_from_file_location(
        module_name,
        os.path.join(os.path.dirname(__file__), file_name)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# Load modules
domain_commands = _load_module('domain_commands', 'domain-commands.py')
security_commands = _load_module('security_commands', 'security-commands.py')
admin_commands = _load_module('admin_commands', 'admin-commands.py')

# Import command functions
start_command = domain_commands.start_command
help_command = domain_commands.help_command
add_domain_command = domain_commands.add_domain_command
remove_domain_command = domain_commands.remove_domain_command
list_domains_command = domain_commands.list_domains_command
whoami_command = domain_commands.whoami_command

audit_command = security_commands.audit_command
renew_command = security_commands.renew_command
set_interval_command = security_commands.set_interval_command

grant_admin_command = admin_commands.grant_admin_command
grant_viewer_command = admin_commands.grant_viewer_command
revoke_command = admin_commands.revoke_command
list_users_command = admin_commands.list_users_command

__all__ = [
    # Domain commands
    'start_command',
    'help_command',
    'add_domain_command',
    'remove_domain_command',
    'list_domains_command',
    'whoami_command',
    # Security commands
    'audit_command',
    'renew_command',
    'set_interval_command',
    # Admin commands
    'grant_admin_command',
    'grant_viewer_command',
    'revoke_command',
    'list_users_command',
]
