# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do NOT open public issues for security vulnerabilities.**

Instead, email security reports to: [your-email]

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and work on a fix promptly.

## Security Best Practices

When deploying CertSentinel:

1. **Environment Variables**: Never commit `.env` files with real credentials
2. **Bot Token**: Store BOT_TOKEN securely, rotate regularly
3. **Admin Access**: Limit ADMIN_IDS to trusted users only
4. **Updates**: Keep dependencies updated (`pip install -U -r requirements.txt`)
5. **Monitoring**: Review logs regularly for suspicious activity
6. **Network**: Run behind firewall, restrict database access
7. **Backups**: Backup `certsentinel.db` regularly

## Known Security Features

- Input validation on all user inputs
- No shell command injection (subprocess uses list args)
- Parameterized SQL queries (no SQL injection)
- RBAC enforcement with decorators
- Rate limiting on external API calls
- Timeout handling for all network operations

## Security Audit

Last security review: February 2026
Review score: 8.5/10

Critical issues: 0
High priority issues: 0
Medium priority issues: 0
