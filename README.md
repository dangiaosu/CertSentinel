# 🔒 CertSentinel Bot

**Infrastructure & Security Monitoring Telegram Bot**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

CertSentinel is a comprehensive Telegram bot designed for developers and system administrators to monitor their infrastructure. Track SSL certificate expiry, website uptime, domain registration, and run security audits - all from Telegram.

---

## ✨ Features

### 🔍 Comprehensive Monitoring
- **SSL Certificate Monitoring**: Track certificate expiry, alert 7 days before expiration
- **Uptime Monitoring**: Check website availability every 5 minutes
- **Domain Expiry Monitoring**: WHOIS-based domain registration tracking
- **Latency Tracking**: Alert when response time exceeds 2 seconds

### 🛡️ Security Audits
- **HTTP Security Headers Check**: Validate HSTS, CSP, X-Frame-Options, and more
- **Port Scanning**: Detect publicly exposed dangerous ports (SSH, MySQL, Redis, etc.)
- **Security Scoring**: Letter grade (A-F) based on security posture
- **Actionable Recommendations**: Get specific suggestions to improve security

### 👥 Team Collaboration
- **Role-Based Access Control (RBAC)**: Admin and Viewer roles
- **Group Chat Support**: Use in Telegram groups with your team
- **Multi-User**: Support for multiple administrators and viewers
- **Audit Trail**: All actions logged with user attribution

### 🚀 Automation
- **Background Monitoring**: Automatic checks run at configurable intervals
- **Smart Alerts**: Only notify on state changes to avoid spam
- **Mock SSL Renewal**: Simulate certificate renewal with certbot integration
- **Configurable Thresholds**: Customize alert timings for your needs

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Telegram Bot API                         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                         bot.py                               │
│  • Command Handlers                                          │
│  • Background Job Scheduler                                  │
│  • Alert Dispatcher                                          │
└─────────────────────────────────────────────────────────────┘
           ↓                    ↓                    ↓
┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐
│   Monitors       │  │   Scanner        │  │   Database      │
│  • SSL Check     │  │  • Headers Check │  │  • SQLite       │
│  • Uptime Check  │  │  • Port Scan     │  │  • RBAC         │
│  • Domain Check  │  │  • Score Calc    │  │  • Scan History │
└──────────────────┘  └──────────────────┘  └─────────────────┘
```

---

## 📋 Prerequisites

- Python 3.10 or higher
- Telegram Bot Token (from [@BotFather](https://t.me/botfather))
- Basic knowledge of environment variables

---

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/certsentinel-bot.git
cd certsentinel-bot/CertSentinel
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment
```bash
cp .env.example .env
# Edit .env with your bot token and admin IDs
```

Required environment variables:
- `BOT_TOKEN`: Your Telegram bot token from BotFather
- `ADMIN_IDS`: Comma-separated list of admin user IDs (get from [@userinfobot](https://t.me/userinfobot))

### 4. Run the Bot
```bash
python bot.py
```

The bot will:
1. Initialize the SQLite database
2. Create the initial admin user
3. Start listening for commands
4. Begin background monitoring jobs

---

## 📖 Usage

### Basic Commands

**Domain Management** (Admin only)
```
/add google.com          # Add domain to monitoring
/remove google.com       # Remove domain
/list                    # List all monitored domains
```

**Security Audits** (All users)
```
/audit google.com        # Run security audit
```

**Administration** (Admin only)
```
/grant_admin 123456789   # Grant admin role to user
/grant_viewer 987654321  # Grant viewer role to user
/revoke 123456789        # Revoke user access
/list_users              # List all users
```

**Information**
```
/start                   # Welcome message
/help                    # Show all commands
/whoami                  # Check your role
```

### Mock SSL Renewal
```
/renew google.com        # Simulate SSL renewal (admin only)
```

---

## ⚙️ Configuration

All configuration is done via environment variables. See `.env.example` for full list.

### Key Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `BOT_TOKEN` | *required* | Telegram bot token |
| `ADMIN_IDS` | *required* | Comma-separated admin user IDs |
| `UPTIME_INTERVAL` | 300 | Uptime check interval (seconds) |
| `SSL_INTERVAL` | 21600 | SSL check interval (6 hours) |
| `DOMAIN_INTERVAL` | 86400 | Domain check interval (24 hours) |
| `SSL_WARNING_DAYS` | 7 | SSL warning threshold (days) |
| `DOMAIN_WARNING_DAYS` | 30 | Domain warning threshold (days) |
| `LATENCY_THRESHOLD` | 2.0 | Latency alert threshold (seconds) |

---

## 🔐 Security Considerations

### Best Practices
1. **Protect Your Bot Token**: Never commit `.env` to version control
2. **Limit Admin Access**: Only grant admin role to trusted users
3. **Use Groups Wisely**: Consider private groups for sensitive infrastructure
4. **Review Logs**: Regularly check `certsentinel.log` for suspicious activity
5. **Update Dependencies**: Keep python-telegram-bot and other libraries up to date

### RBAC Model
- **Admin**: Can add/remove domains, manage users, trigger renewals
- **Viewer**: Can view status, run audits, receive notifications

### Database Security
- SQLite database stored locally with restrictive permissions
- No sensitive data stored unencrypted
- Parameterized queries prevent SQL injection

---

## 🧪 Testing

### Manual Testing
```bash
# Test individual monitors
python -c "import asyncio; from monitors.ssl_monitor import check_ssl_expiry; print(asyncio.run(check_ssl_expiry('google.com')))"
```

### Check Database
```bash
sqlite3 certsentinel.db "SELECT * FROM domains;"
```

---

## 📁 Project Structure

```
CertSentinel/
├── bot.py                    # Main bot application
├── db.py                     # Database operations
├── scanner.py                # Security audit engine
├── monitors/                 # Monitoring modules
│   ├── ssl_monitor.py
│   ├── uptime_monitor.py
│   └── domain_monitor.py
├── handlers/                 # Command handlers
│   ├── domain_commands.py
│   ├── security_commands.py
│   └── admin_commands.py
├── utils/                    # Utilities
│   ├── formatters.py
│   ├── auth.py
│   ├── config.py
│   └── security_helpers.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guide
- Add docstrings to all functions
- Test your changes before submitting PR
- Update documentation as needed

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🙏 Acknowledgments

- [python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot) - Excellent Telegram Bot API wrapper
- [python-whois](https://github.com/richardpenman/whois) - WHOIS library
- All contributors who help improve this project

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/certsentinel-bot/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/certsentinel-bot/discussions)
- **Security**: Report security vulnerabilities privately to security@yourdomain.com

---

## 🗺️ Roadmap

- [ ] Web dashboard for non-Telegram users
- [ ] Integration with Slack, Discord
- [ ] Custom alerting rules engine
- [ ] Prometheus metrics export
- [ ] Docker image and Kubernetes manifests
- [ ] Multi-language support

---

**Made with ❤️ for DevOps Engineers**
