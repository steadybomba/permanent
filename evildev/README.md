<p align="center"> <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python 3.8+"> <img src="https://img.shields.io/badge/Flask-2.3.3-green.svg" alt="Flask 2.3.3"> <img src="https://img.shields.io/badge/Status-Production%20Ready-red.svg" alt="Production Ready"> <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT License"> </p>
🔥 Overview
THE COLLECTIVE is an OAuth device-code capture and email campaign application for authorized security testing.

⚠️ WARNING: This tool is for AUTHORIZED USE ONLY. Unauthorized use is illegal and strictly prohibited. Use only on systems you own or have explicit permission to test.

✨ Features
🎯 Token Harvesting
OAuth Device Code Flow - Stealthy token harvesting with Microsoft's device code flow

Conditional Access Detection - Detects MFA, compliant device, and location policies

Token Refresh Management - CA-aware refresh with self-healing capabilities

Playwright Support - Deep cookie extraction via headless browsers

Parallel Cookie Extraction - Multi-threaded cookie harvesting

📧 Advanced Email Sender
Content Stuffing - ML evasion with invisible legitimate content

Per-Recipient Token Randomization - Unique tracking tokens for each recipient

Dynamic Bait Generation - Organization-aware personalized emails

SMTP Support - TLS/SSL with authentication

Rate Limiting - Per-hour and per-day sending limits

Campaign Management - Multi-recipient campaigns with analytics

📤 Exfiltration
Multiple Channels - Telegram, Discord, HTTP webhooks

AES-256 Encryption - Encrypted payload delivery

Real-time Exfil - Immediate exfiltration on token capture

Validation Endpoints - Test and validate channel configurations

🛡️ Stealth & Security
Proxy Rotation - Automatic proxy rotation with health checking

Network Resilience - DNS fallback, retry logic, connection pooling

User-Agent Rotation - Platform diversity for evasion

Jitter & Delays - Human-like timing patterns

Anti-Spam Headers - Proper email formatting for deliverability

🎛️ Dashboards
God Mode Dashboard - Cyberpunk-themed command center with 3D visuals

Sender Dashboard - Dedicated email orchestration interface

Real-time SSE Updates - Live status updates via Server-Sent Events

Comprehensive Analytics - Campaign metrics, token statistics, and health monitoring

📋 Prerequisites
Python 3.8+

pip (Python package manager)

Git (for cloning)

SMTP Server (for email sending, e.g., Gmail, Office 365)

🚀 Quick Start
1. Clone the Repository
bash
git clone https://github.com/your-org/the-collective.git
cd the-collective
2. Run the Installer
Linux/macOS
bash
chmod +x start.sh
./start.sh
Windows
cmd
start.bat
3. Access the Dashboards
Main Dashboard: http://localhost:5000/

Sender Dashboard: http://localhost:5000/senderdashboard

4. Configure
Edit the .env file with your settings:

env
# Core Configuration
CLIENT_ID=your_azure_client_id
TENANT=common
AUTH_USER=admin
AUTH_PASS=your_secure_password

# SMTP Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
📁 Project Structure
text
the-collective/
├── app.py                      # Main Flask application
├── harvester.py                # Token harvester
├── token_refresh_manager.py    # Token refresh management
├── proxy_manager.py            # Proxy management
├── core.py                     # Core utilities
├── db.py                       # Database layer
├── logger.py                   # Enhanced logging
├── exfil.py                    # Exfiltration manager
├── email_sender.py             # Advanced email sender
├── content_stuffer.py          # ML evasion module
├── token_randomizer.py         # Token randomization
├── dynamic_bait_generator.py   # Dynamic bait generation
├── network_resilience.py       # Network resilience
├── requirements.txt            # Python dependencies
├── .env                        # Configuration
├── start.sh                    # Linux/macOS launcher
├── start.bat                   # Windows launcher
├── data/
├── templates/
│   ├── dashboard.html          # Main dashboard
│   ├── senderdashboard.html    # Sender dashboard
│   └── login.html              # Login page
├── static/                     # Static assets
├── email_templates/            # Email templates
└── content_dictionaries/       # Content stuffing dictionaries
🎯 Usage Examples
Starting a Capture Session
python
# Through the dashboard
# 1. Navigate to http://localhost:5000/
# 2. Enter CLIENT_ID and Tenant
# 3. Click "Start Capture"
# 4. Present the device code to the target

# Through API
curl -X POST http://localhost:5000/api/async/start-capture \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your_client_id",
    "tenant": "common",
    "scope": "openid offline_access profile Mail.Send"
  }'
Sending a Campaign
python
from email_sender import get_campaign_manager

campaign_manager = get_campaign_manager()

targets = [
    {
        'email': 'ceo@company.com',
        'role': 'executive',
        'context': {
            'name': 'CEO Name',
            'score': 95,
            'quarter': 'Q4 2026'
        },
        'template': 'executive_briefing'
    }
]

campaign_id = campaign_manager.start_campaign(
    targets,
    campaign_name="Q4 Board Briefing"
)
Using the API
bash
# Send a test email
curl -X POST http://localhost:5000/api/email/send \
  -H "Content-Type: application/json" \
  -d '{
    "to_email": "test@company.com",
    "template_name": "account_security",
    "context": {
      "name": "Test User",
      "user_code": "ABC123"
    }
  }'

📊 API Endpoints
Category	Endpoints
Capture	/api/async/start-capture, /api/finalize/<id>, /api/stream/<id>
Email	/api/email/* (templates, send, campaign, stats)
Proxy	/api/proxy/* (test, status, next, count)
Exfil	/api/exfil/* (test, validate, ping)
Tokens	/api/tokens/* (stats, verify, revoke)
Config	/api/config/* (list, save, load, delete, apply)
Tracking	/tracking/pixel, /tracking/r, /tracking/open
🔧 Configuration
Environment Variables
Variable	Description	Default
CLIENT_ID	Azure AD Client ID	-
TENANT	Azure AD Tenant	common
AUTH_USER	Dashboard username	admin
AUTH_PASS	Dashboard password	-
SMTP_HOST	SMTP server host	-
SMTP_PORT	SMTP server port	587
SMTP_USERNAME	SMTP username	-
SMTP_PASSWORD	SMTP password	-
TRACKING_BASE_URL	Base URL for tracking	http://localhost:5000
PROXY_LIST	Comma-separated proxies	-
Email Templates
Create custom templates in email_templates/:

text
email_templates/
├── my_template.html
├── my_template.txt
└── my_template.meta.json
Meta JSON example:

json
{
    "name": "my_template",
    "subject": "Custom subject line",
    "category": "general",
    "score_threshold": 50,
    "target_roles": ["executive", "manager"]
}
🛡️ Security Best Practices
Enable Authentication: Set REQUIRE_AUTH=true in .env

Use HTTPS: Deploy behind nginx with SSL certificates

Rotate Encryption Keys: Change ENCRYPTION_KEY regularly

Monitor Logs: Check logs/ directory for activity

Limit Access: Use firewall rules to restrict to authorized IPs

Regular Updates: Keep the tool updated with latest security patches

Audit Logs: Enable detailed logging for audit trails

🐛 Troubleshooting
Common Issues
SMTP Connection Failed

bash
# Check credentials and network connectivity
curl -v smtp://smtp.gmail.com:587
Proxy Connection Failed

bash
# Test proxy connectivity
curl -x http://proxy:8080 https://api.ipify.org
Database Locked

bash
# Check if another instance is running
ps aux | grep python | grep app.py
Playwright Not Found

bash
# Reinstall Playwright
playwright install chromium
📈 Performance Tuning
Recommended Settings
Setting	Value	Description
MAX_CAPTURE_WORKERS	4	Concurrent capture sessions
EMAIL_MAX_PER_HOUR	50	Emails per hour limit
EMAIL_DELAY_MIN	5	Minimum delay between emails
CONNECTION_POOL_SIZE	50	Network connection pool
🤝 Contributing
Fork the repository

Create a feature branch

Commit your changes

Push to the branch

Open a Pull Request

Code Style
Follow PEP 8 guidelines

Use type hints

Write docstrings for functions

Add appropriate logging

📝 License
This project is licensed under the MIT License - see the LICENSE file for details.

⚠️ Disclaimer
THE COLLECTIVE is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before using this tool. The creators assume no liability for misuse.

🙏 Acknowledgments
Microsoft Graph API documentation

OAuth 2.0 Device Code Flow specification

Various open-source libraries and tools

📞 Support
For issues and questions, please open an issue on GitHub.

<p align="center"> <strong>THE COLLECTIVE</strong><br> <em>Authorized Use Only</em> </p><p align="center"> Made with ❤️ for authorized red team operations </p>