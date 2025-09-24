# Lighter Security Scanner

Advanced web and server scanning tool for security assessment.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Basic scan
python lighter.py target.com

# Save results
python lighter.py target.com -o results.json
```

## Features

- 🔍 **Web Server Detection** - Apache, Nginx, Lighttpd, IIS
- 📧 **Email Server Detection** - Sendmail, Postfix, Exim, Dovecot  
- 🗄️ **Database Detection** - MySQL, PostgreSQL, Redis, MongoDB
- 🚀 **Framework Detection** - Django, Flask, Spring, Rails, Laravel
- 🎯 **CMS Detection** - WordPress, Joomla, Drupal, Magento
- 🔄 **CI/CD Detection** - Jenkins, GitLab, Drone, Travis
- 🐳 **Container Detection** - Kubernetes, Docker, Hadoop
- 🔒 **Vulnerability Detection** - Security misconfigurations

## Usage

```bash
# Scan target
python lighter.py example.com

# Custom options
python lighter.py target.com -t 100 --timeout 15 -v

# Text output
python lighter.py target.com -f txt -o report.txt
```

## Author

**SayerLinux** - SaudiLinux1@gmail.com