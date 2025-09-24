# Lighter Security Scanner

## Overview
Lighter is a comprehensive security scanning tool designed to detect various web servers, email servers, databases, applications, frameworks, and vulnerabilities without requiring authentication. Developed by SayerLinux (SaudiLinux1@gmail.com), this tool provides extensive coverage for security assessments and reconnaissance.

## Features

### 🔍 **Web Server Detection**
- **Apache HTTP Server** - Detection via headers and content analysis
- **Nginx** - Web server and reverse proxy detection
- **Lighttpd** - Lightweight web server identification
- **Microsoft IIS** - Internet Information Services detection
- **Additional servers** - Via header analysis and fingerprinting

### 📧 **Email Server Detection**
- **Sendmail** - Mail transfer agent detection
- **Postfix** - SMTP server identification
- **Exim** - Mail server detection
- **Dovecot** - IMAP/POP3 server detection
- **Port scanning** - For SMTP (25, 587), SMTPS (465), IMAP (143, 993), POP3 (110, 995)

### 🗄️ **Database Detection**
- **MySQL** - Port 3306 detection
- **PostgreSQL** - Port 5432 identification
- **Redis** - Port 6379 detection
- **MongoDB** - Port 27017 identification
- **Memcached** - Port 11211 detection

### 🚀 **Framework Detection**
- **Django** - Python web framework
- **Flask** - Python micro-framework
- **Spring Framework** - Java enterprise framework
- **Ruby on Rails** - Ruby web framework
- **Laravel** - PHP framework
- **Express.js** - Node.js framework
- **ASP.NET** - Microsoft framework
- **PHP** - Core PHP detection

### 🎯 **CMS Platform Detection**
- **WordPress** - Via wp-content, wp-includes paths
- **Joomla** - Component and module detection
- **Drupal** - Sites directory and core files
- **Magento** - E-commerce platform detection
- **OpenCart** - Shopping cart detection
- **PrestaShop** - E-commerce solution detection

### 🔄 **CI/CD Platform Detection**
- **Jenkins** - Automation server detection
- **GitLab** - DevOps platform identification
- **Drone CI** - Continuous integration platform
- **Travis CI** - Build automation detection
- **GoCD** - Continuous delivery tool
- **GitHub Actions** - Workflow automation

### 🐳 **Container & Orchestration Detection**
- **Kubernetes** - Container orchestration
- **Docker** - Container platform
- **Apache Hadoop** - Big data framework
- **HashiCorp Consul** - Service mesh
- **HashiCorp Nomad** - Workload orchestration

### 🔒 **Vulnerability Detection**
- **Directory Listing** - Enabled directory browsing
- **Server Version Disclosure** - Information leakage
- **Missing Security Headers** - X-Frame-Options, X-Content-Type-Options
- **Insecure Cookie Configuration** - Missing Secure/HttpOnly flags
- **Authentication Bypass** - Common misconfigurations

## Installation

### Requirements
```bash
# Python 3.6+
python --version

# Install dependencies
pip install requests
```

### Download
```bash
# Clone or download the tool
git clone <repository-url>
cd lighter
```

## Usage

### Basic Scan
```bash
# Scan a target
python lighter.py target.com

# Scan with custom options
python lighter.py target.com -t 100 --timeout 15
```

### Advanced Usage
```bash
# Save results to file
python lighter.py target.com -o scan_results.json

# Text format output
python lighter.py target.com -f txt -o report.txt

# Verbose output
python lighter.py target.com -v

# Custom thread count
python lighter.py target.com -t 200 --timeout 20
```

### Command Line Options
```
positional arguments:
  target                Target IP address or hostname

optional arguments:
  -h, --help           Show help message and exit
  -t, --threads        Number of threads (default: 50)
  --timeout            Connection timeout in seconds (default: 10)
  -o, --output         Output file path
  -f, --format         Output format: json, txt (default: json)
  -v, --verbose        Verbose output
```

## Scanning Capabilities

### Port Coverage
- **Web Services**: 80, 443, 8080, 8443, 8000, 8888, 3000, 5000
- **Email Services**: 25, 465, 587, 993, 995, 110, 143
- **Database Services**: 3306, 5432, 6379, 11211, 27017, 5984, 9200
- **Application Services**: 3000, 5000, 7000, 8000, 8080, 9000, 9090

### Detection Methods
- **Banner Grabbing** - Service identification via banners
- **Header Analysis** - HTTP header inspection
- **Content Analysis** - Page content and structure analysis
- **Fingerprinting** - Service-specific signatures
- **Protocol Detection** - Multi-protocol support (HTTP/HTTPS)

## Output Formats

### JSON Format
```json
{
  "target": "example.com",
  "scan_time": "2024-01-15 10:30:45",
  "open_ports": [80, 443, 3306, 8080],
  "web_servers": [
    {
      "port": 80,
      "protocol": "http",
      "server_type": "nginx",
      "status_code": 200,
      "frameworks": ["django", "flask"],
      "cms": ["wordpress"],
      "vulnerabilities": [
        {
          "name": "Server Version Disclosure",
          "severity": "low",
          "url": "http://example.com"
        }
      ]
    }
  ],
  "email_servers": [
    {
      "port": 25,
      "server_type": "postfix",
      "banner": "220 mail.example.com ESMTP Postfix"
    }
  ],
  "databases": [
    {
      "port": 3306,
      "server_type": "mysql",
      "response": "5.7.32"
    }
  ]
}
```

### Text Format
```
Lighter Security Scanner Report
===============================
Target: example.com
Scan Time: 2024-01-15 10:30:45
Developer: SayerLinux (SaudiLinux1@gmail.com)

Open Ports: 80, 443, 3306, 8080

Web Servers Detected:
  - Nginx on port 80 (http)
    Frameworks: django, flask
    CMS: wordpress
    Vulnerability: Server Version Disclosure (low)

Email Servers Detected:
  - Postfix on port 25

Databases Detected:
  - Mysql on port 3306
```

## Testing

### Unit Tests
```bash
# Run all tests
python test_lighter.py

# Run with verbose output
python test_lighter.py -v
```

### Test Coverage
- Web server detection tests
- Email server detection tests
- Database detection tests
- Framework detection tests
- CMS detection tests
- Vulnerability detection tests
- CLI functionality tests
- Error handling tests
- Performance tests

## Security Considerations

### Responsible Use
- **Authorized Scanning Only** - Use only on systems you own or have permission to test
- **Network Impact** - Be mindful of network load and target system resources
- **Legal Compliance** - Ensure compliance with local laws and regulations
- **Rate Limiting** - Tool includes built-in rate limiting to prevent overwhelming targets

### Detection Avoidance
- **Stealth Mode** - Uses standard HTTP headers and timing
- **Distributed Scanning** - Multi-threaded approach for efficiency
- **Timeout Controls** - Configurable timeouts to prevent hanging
- **Error Handling** - Graceful handling of connection failures

## Performance

### Optimization Features
- **Multi-threading** - Concurrent port scanning and service detection
- **Connection Pooling** - Efficient HTTP connection management
- **Timeout Management** - Configurable timeouts for different scenarios
- **Memory Efficient** - Streaming data processing where possible

### Benchmarks
- **Port Scanning**: ~1000 ports in under 30 seconds
- **Service Detection**: ~50 services in under 2 minutes
- **Full Scan**: Complete assessment in 2-5 minutes
- **Memory Usage**: <100MB for typical scans

## Troubleshooting

### Common Issues
```bash
# Connection timeouts
python lighter.py target.com --timeout 30

# Thread issues
python lighter.py target.com -t 20

# SSL certificate errors
# Tool automatically handles SSL verification bypass

# Permission denied errors
# Ensure proper network permissions
```

### Debug Mode
```bash
# Enable verbose output
python lighter.py target.com -v

# Check network connectivity
ping target.com
nslookup target.com
```

## Contributing

### Development Setup
```bash
# Clone repository
git clone <repository-url>
cd lighter

# Install development dependencies
pip install -r requirements.txt

# Run tests
python test_lighter.py
```

### Code Style
- Follow PEP 8 guidelines
- Use type hints where appropriate
- Include docstrings for all functions
- Add unit tests for new features

## License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## Contact

**Developer**: SayerLinux  
**Email**: SaudiLinux1@gmail.com  
**Project**: Lighter Security Scanner  

## Changelog

### Version 1.0.0
- Initial release
- Web server detection
- Email server detection
- Database scanning
- Framework detection
- CMS platform detection
- CI/CD platform detection
- Container orchestration detection
- Vulnerability detection
- Unit tests
- Documentation

## Disclaimer

This tool is intended for authorized security testing and research purposes only. Users are solely responsible for ensuring compliance with applicable laws and regulations. The developer assumes no liability for misuse or damage caused by this tool.

---

**Remember**: Always obtain proper authorization before scanning any systems. Unauthorized scanning may be illegal and unethical.