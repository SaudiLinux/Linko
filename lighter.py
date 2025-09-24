#!/usr/bin/env python3
"""
Lighter - Advanced Web and Server Scanner
Author: SayerLinux (SaudiLinux1@gmail.com)
Description: Comprehensive scanning tool for web servers, email servers, databases, 
applications, frameworks, and vulnerability detection without authentication.
"""

import socket
import requests
import smtplib
import json
import argparse
import threading
import time
import re
import ssl
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class LighterScanner:
    def __init__(self, target: str, threads: int = 50, timeout: int = 10):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.results = {
            'target': target,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'web_servers': [],
            'email_servers': [],
            'databases': [],
            'frameworks': [],
            'cms_platforms': [],
            'cicd_platforms': [],
            'containers': [],
            'vulnerabilities': [],
            'open_ports': [],
            'services': {},
            'social_engineering': {
                'phishing_indicators': [],
                'email_exposure': [],
                'social_media_links': [],
                'human_factor_vulnerabilities': [],
                'trust_exploitation': []
            },
            'cryptographic': {
                'key_exposure': [],
                'certificate_exposure': [],
                'ssl_weakness': [],
                'weak_crypto': [],
                'hardcoded_secrets': [],
                'artifact_signing': [],
                'code_signing': []
            },
            'cloud': {
                'cloud_credentials': [],
                'cloud_storage': [],
                'cloud_api': [],
                'cloud_infrastructure': [],
                'cloud_orchestration': [],
                'cloud_container': [],
                'cloud_database': [],
                'cloud_serverless': [],
                'cloud_iam': [],
                'cloud_network': [],
                'cloud_encryption': [],
                'cloud_logging': [],
                'cloud_backup': []
            }
        }
        
        # Common ports for different services
        self.web_ports = [80, 443, 8080, 8081, 8443, 8000, 8888, 3000, 5000]
        self.email_ports = [25, 465, 587, 993, 995, 110, 143]
        self.db_ports = [3306, 5432, 6379, 11211, 27017, 5984, 9200]
        self.app_ports = [3000, 5000, 7000, 8000, 8080, 8081, 9000, 9090]
        
        # Detection signatures
        self.signatures = {
            'web_servers': {
                'apache': {
                    'headers': ['Apache', 'apache'],
                    'content': ['Apache', 'apache'],
                    'ports': [80, 443, 8080]
                },
                'nginx': {
                    'headers': ['nginx', 'Nginx'],
                    'content': ['nginx', 'Nginx'],
                    'ports': [80, 443, 8080, 8443]
                },
                'lighttpd': {
                    'headers': ['lighttpd', 'Lighttpd'],
                    'content': ['lighttpd', 'Lighttpd'],
                    'ports': [80, 443, 8080]
                },
                'iis': {
                    'headers': ['Microsoft-IIS', 'IIS'],
                    'content': ['IIS', 'Internet Information Services'],
                    'ports': [80, 443, 8080]
                }
            },
            'email_servers': {
                'sendmail': {
                    'banner': ['Sendmail', 'sendmail'],
                    'ports': [25, 587]
                },
                'postfix': {
                    'banner': ['Postfix', 'postfix'],
                    'ports': [25, 587]
                },
                'exim': {
                    'banner': ['Exim', 'exim'],
                    'ports': [25, 587]
                },
                'dovecot': {
                    'banner': ['Dovecot', 'dovecot'],
                    'ports': [993, 995, 110, 143]
                }
            },
            'databases': {
                'mysql': {
                    'banner': ['mysql', 'MySQL'],
                    'ports': [3306]
                },
                'postgresql': {
                    'banner': ['PostgreSQL', 'postgres'],
                    'ports': [5432]
                },
                'redis': {
                    'banner': ['redis', 'Redis'],
                    'ports': [6379]
                },
                'mongodb': {
                    'banner': ['MongoDB', 'mongodb'],
                    'ports': [27017]
                }
            }
        }

    def scan_ports(self) -> List[int]:
        """Scan for open ports using threading"""
        print(f"[*] Starting port scan on {self.target}")
        open_ports = []
        ports_to_scan = list(set(self.web_ports + self.email_ports + self.db_ports + self.app_ports))
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                sock.close()
                if result == 0:
                    return port
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports_to_scan}
            for future in as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append(port)
                    print(f"[+] Port {port} is open")
        
        self.results['open_ports'] = sorted(open_ports)
        return open_ports

    def detect_web_server(self, port: int) -> Dict:
        """Detect web server type and version"""
        try:
            protocols = ['http', 'https']
            for protocol in protocols:
                url = f"{protocol}://{self.target}:{port}"
                try:
                    response = requests.get(url, timeout=self.timeout, verify=False, 
                                          headers={'User-Agent': 'Lighter-Scanner/1.0'})
                    
                    server_info = {
                        'port': port,
                        'protocol': protocol,
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'server_type': 'unknown',
                        'sensitive_files': [],
                        'vulnerability_links': []  # Add this field
                    }
                    
                    # Check server header
                    server_header = response.headers.get('Server', '').lower()
                    
                    # Detect web server type
                    for server_type, signatures in self.signatures['web_servers'].items():
                        if any(sig.lower() in server_header for sig in signatures['headers']):
                            server_info['server_type'] = server_type
                            break
                    
                    # Additional detection methods
                    if server_info['server_type'] == 'unknown':
                        content = response.text.lower()
                        for server_type, signatures in self.signatures['web_servers'].items():
                            if any(sig.lower() in content for sig in signatures['content']):
                                server_info['server_type'] = server_type
                                break
                    
                    # Detect frameworks and CMS
                    self.detect_frameworks(response, server_info)
                    self.detect_cms(response, server_info)
                    self.detect_vulnerabilities(response, url, server_info)
                    
                    # Detect social engineering vulnerabilities
                    social_eng_vulns = self.detect_social_engineering_vulnerabilities(response, url, server_info)
                    server_info['social_engineering_vulnerabilities'] = social_eng_vulns
                    
                    # Detect cryptographic vulnerabilities
                    crypto_vulns = self.detect_cryptographic_vulnerabilities(response, url, server_info)
                    server_info['cryptographic_vulnerabilities'] = crypto_vulns
                    
                    # Detect cloud vulnerabilities
                    cloud_vulns = self.detect_cloud_vulnerabilities(response, url, server_info)
                    server_info['cloud_vulnerabilities'] = cloud_vulns
                    
                    # Discover sensitive files
                    sensitive_files = self.discover_sensitive_files(self.target, protocol)
                    server_info['sensitive_files'] = sensitive_files
                    
                    # Discover vulnerability links
                    vulnerability_links = self.discover_vulnerability_links(self.target, protocol)
                    server_info['vulnerability_links'] = vulnerability_links
                    
                    return server_info
                    
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"[-] Error detecting web server on port {port}: {e}")
            
        return None

    def detect_frameworks(self, response: requests.Response, server_info: Dict):
        """Detect web frameworks"""
        content = response.text.lower()
        headers = response.headers
        
        frameworks = {
            'django': ['csrftoken', 'django', 'django_language'],
            'flask': ['flask', 'werkzeug'],
            'spring': ['spring', 'spring-security'],
            'rails': ['rails', 'ruby on rails'],
            'laravel': ['laravel_session', 'laravel'],
            'express': ['express', 'connect.sid'],
            'asp.net': ['asp.net', 'asp.net_sessionid'],
            'php': ['php', 'php_session_id']
        }
        
        detected_frameworks = []
        for framework, indicators in frameworks.items():
            if any(indicator in content or indicator in str(headers).lower() for indicator in indicators):
                detected_frameworks.append(framework)
        
        server_info['frameworks'] = detected_frameworks

    def detect_cms(self, response: requests.Response, server_info: Dict):
        """Detect CMS platforms"""
        content = response.text.lower()
        
        cms_signatures = {
            'wordpress': ['/wp-content/', '/wp-includes/', 'wp-json', 'wordpress'],
            'joomla': ['/components/', '/modules/', 'joomla'],
            'drupal': ['/sites/default/', 'drupal', 'drupal.js'],
            'magento': ['magento', 'mage', 'magento_version'],
            'opencart': ['opencart', 'route=common'],
            'prestashop': ['prestashop', 'ps_version']
        }
        
        detected_cms = []
        for cms, indicators in cms_signatures.items():
            if any(indicator in content for indicator in indicators):
                detected_cms.append(cms)
        
        server_info['cms'] = detected_cms

    def detect_email_server(self, port: int) -> Dict:
        """Detect email server type"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            # Get banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            email_info = {
                'port': port,
                'banner': banner,
                'server_type': 'unknown',
                'secure': port in [465, 993, 995]
            }
            
            # Detect email server type
            for server_type, signatures in self.signatures['email_servers'].items():
                if any(sig.lower() in banner.lower() for sig in signatures['banner']):
                    email_info['server_type'] = server_type
                    break
            
            sock.close()
            return email_info
            
        except Exception as e:
            print(f"[-] Error detecting email server on port {port}: {e}")
            return None

    def detect_database(self, port: int) -> Dict:
        """Detect database servers"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            # Send probe based on port
            if port == 3306:  # MySQL
                sock.send(b"\x05\x00\x00\x01\x85\xa6\x03\x00\x00\x00\x00\x01\x08\x00\x00\x00")
            elif port == 5432:  # PostgreSQL
                sock.send(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
            elif port == 6379:  # Redis
                sock.send(b"*1\r\n$4\r\nPING\r\n")
            
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            db_info = {
                'port': port,
                'response': response[:100],
                'server_type': 'unknown'
            }
            
            # Detect database type
            for db_type, signatures in self.signatures['databases'].items():
                if port in signatures['ports']:
                    db_info['server_type'] = db_type
                    break
            
            sock.close()
            return db_info
            
        except Exception as e:
            print(f"[-] Error detecting database on port {port}: {e}")
            return None

    def detect_cicd_platforms(self, port: int) -> List[Dict]:
        """Detect CI/CD platforms"""
        cicd_platforms = {
            'jenkins': ['/jenkins/', '/api/json', 'jenkins-agent'],
            'gitlab': ['/api/v4/', '/explore', 'gitlab-logo'],
            'drone': ['/api/repos', '/api/user', 'drone.io'],
            'travis': ['travis-ci', 'travis'],
            'gocd': ['/go/', 'gocd'],
            'github-actions': ['github-actions', 'actions/checkout']
        }
        
        detected = []
        protocols = ['http', 'https']
        
        for protocol in protocols:
            url = f"{protocol}://{self.target}:{port}"
            try:
                response = requests.get(url, timeout=self.timeout, verify=False)
                content = response.text.lower()
                
                for platform, indicators in cicd_platforms.items():
                    if any(indicator in content for indicator in indicators):
                        detected.append({
                            'platform': platform,
                            'port': port,
                            'protocol': protocol,
                            'url': url
                        })
                        
            except:
                continue
                
        return detected

    def detect_containers(self, port: int) -> List[Dict]:
        """Detect container and orchestration platforms"""
        container_platforms = {
            'kubernetes': ['/api/v1/', 'kubernetes', 'kube-api'],
            'docker': ['/version', 'docker', 'Docker'],
            'hadoop': ['/jmx', 'hadoop', 'hdfs'],
            'consul': ['/v1/status/leader', 'consul'],
            'nomad': ['/v1/status/leader', 'nomad']
        }
        
        detected = []
        protocols = ['http', 'https']
        
        for protocol in protocols:
            url = f"{protocol}://{self.target}:{port}"
            try:
                response = requests.get(url, timeout=self.timeout, verify=False)
                content = response.text.lower()
                
                for platform, indicators in container_platforms.items():
                    if any(indicator in content for indicator in indicators):
                        detected.append({
                            'platform': platform,
                            'port': port,
                            'protocol': protocol,
                            'url': url
                        })
                        
            except:
                continue
                
        return detected

    def detect_vulnerabilities(self, response: requests.Response, url: str, server_info: Dict):
        """Detect common vulnerabilities without authentication"""
        vulnerabilities = []
        
        # Check for common vulnerability indicators
        checks = [
            {
                'name': 'Directory Listing Enabled',
                'check': lambda r: 'Index of /' in r.text or 'directory listing' in r.text.lower(),
                'severity': 'medium'
            },
            {
                'name': 'Server Version Disclosure',
                'check': lambda r: bool(r.headers.get('Server')) and len(r.headers.get('Server', '')) > 0,
                'severity': 'low'
            },
            {
                'name': 'X-Frame-Options Missing',
                'check': lambda r: 'X-Frame-Options' not in r.headers,
                'severity': 'medium'
            },
            {
                'name': 'X-Content-Type-Options Missing',
                'check': lambda r: 'X-Content-Type-Options' not in r.headers,
                'severity': 'low'
            },
            {
                'name': 'Insecure Cookie Configuration',
                'check': lambda r: any('Secure' not in cookie or 'HttpOnly' not in cookie for cookie in r.cookies.values()),
                'severity': 'medium'
            }
        ]
        
        for vuln_check in checks:
            if vuln_check['check'](response):
                vulnerabilities.append({
                    'name': vuln_check['name'],
                    'severity': vuln_check['severity'],
                    'url': url
                })
        
        server_info['vulnerabilities'] = vulnerabilities

    def detect_social_engineering_vulnerabilities(self, response: requests.Response, url: str, server_info: Dict):
        """Detect social engineering attack vectors and human-factor vulnerabilities"""
        social_eng_vulns = []
        
        # Phishing indicators
        phishing_checks = [
            {
                'name': 'Login Form Without HTTPS',
                'check': lambda r, u: 'login' in r.text.lower() and not u.startswith('https'),
                'severity': 'high',
                'type': 'phishing_vector'
            },
            {
                'name': 'Password Field on HTTP',
                'check': lambda r, u: 'type="password"' in r.text.lower() and not u.startswith('https'),
                'severity': 'high',
                'type': 'phishing_vector'
            },
            {
                'name': 'External Form Submissions',
                'check': lambda r, u: any('action="http' in r.text and 'action="http' not in u for _ in [0]),
                'severity': 'medium',
                'type': 'phishing_vector'
            },
            {
                'name': 'Suspicious Domain Similarity',
                'check': lambda r, u: self.check_domain_similarity(u),
                'severity': 'high',
                'type': 'phishing_vector'
            }
        ]
        
        # Email exposure checks
        email_checks = [
            {
                'name': 'Email Addresses in Source',
                'check': lambda r, u: bool(re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', r.text)),
                'severity': 'medium',
                'type': 'email_exposure'
            },
            {
                'name': 'Contact Forms Exposed',
                'check': lambda r, u: 'contact' in r.text.lower() and 'form' in r.text.lower(),
                'severity': 'low',
                'type': 'email_exposure'
            },
            {
                'name': 'Mailto Links Present',
                'check': lambda r, u: 'mailto:' in r.text.lower(),
                'severity': 'low',
                'type': 'email_exposure'
            }
        ]
        
        # Social media exposure
        social_media_checks = [
            {
                'name': 'Social Media Widgets',
                'check': lambda r, u: any(social in r.text.lower() for social in ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com']),
                'severity': 'low',
                'type': 'social_exposure'
            },
            {
                'name': 'Share Buttons Present',
                'check': lambda r, u: 'share' in r.text.lower() and ('facebook' in r.text.lower() or 'twitter' in r.text.lower()),
                'severity': 'low',
                'type': 'social_exposure'
            },
            {
                'name': 'Social Login Options',
                'check': lambda r, u: any(login in r.text.lower() for login in ['login with google', 'login with facebook', 'login with twitter']),
                'severity': 'medium',
                'type': 'social_exposure'
            }
        ]
        
        # Human factor vulnerabilities
        human_factor_checks = [
            {
                'name': 'Default Credentials Hint',
                'check': lambda r, u: any(hint in r.text.lower() for hint in ['default password', 'default login', 'admin/admin']),
                'severity': 'high',
                'type': 'human_factor'
            },
            {
                'name': 'Password Recovery Weakness',
                'check': lambda r, u: 'password hint' in r.text.lower() or 'security question' in r.text.lower(),
                'severity': 'medium',
                'type': 'human_factor'
            },
            {
                'name': 'Username Enumeration',
                'check': lambda r, u: 'invalid username' in r.text.lower() or 'user not found' in r.text.lower(),
                'severity': 'medium',
                'type': 'human_factor'
            },
            {
                'name': 'Helpful Error Messages',
                'check': lambda r, u: len(re.findall(r'(user|username|password|invalid|incorrect)', r.text.lower())) > 3,
                'severity': 'low',
                'type': 'human_factor'
            }
        ]
        
        # Trust exploitation vectors
        trust_exploitation_checks = [
            {
                'name': 'HTTP Content on HTTPS Site',
                'check': lambda r, u: u.startswith('https') and ('http://' in r.text or 'src="http' in r.text),
                'severity': 'medium',
                'type': 'trust_exploitation'
            },
            {
                'name': 'External JavaScript Inclusion',
                'check': lambda r, u: 'src="http' in r.text and any(js in r.text for js in ['jquery', 'bootstrap', 'angular']),
                'severity': 'medium',
                'type': 'trust_exploitation'
            },
            {
                'name': 'Mixed Content Warnings',
                'check': lambda r, u: u.startswith('https') and ('http://' in r.text or 'ws://' in r.text),
                'severity': 'medium',
                'type': 'trust_exploitation'
            },
            {
                'name': 'Third-Party Form Actions',
                'check': lambda r, u: any('action="http' in r.text and domain not in u for domain in re.findall(r'action="([^"]+)"', r.text)),
                'severity': 'high',
                'type': 'trust_exploitation'
            }
        ]
        
        # Run all checks
        all_checks = [
            ('phishing_indicators', phishing_checks),
            ('email_exposure', email_checks),
            ('social_media_links', social_media_checks),
            ('human_factor_vulnerabilities', human_factor_checks),
            ('trust_exploitation', trust_exploitation_checks)
        ]
        
        for vuln_category, checks in all_checks:
            for check in checks:
                try:
                    if check['check'](response, url):
                        vulnerability = {
                            'name': check['name'],
                            'severity': check['severity'],
                            'type': check['type'],
                            'url': url,
                            'description': self.get_social_engineering_description(check['name']),
                            'mitigation': self.get_social_engineering_mitigation(check['name'])
                        }
                        social_eng_vulns.append(vulnerability)
                        self.results['social_engineering'][vuln_category].append(vulnerability)
                except:
                    continue
        
        return social_eng_vulns
    
    def check_domain_similarity(self, url: str) -> bool:
        """Check for suspicious domain similarity that could indicate typosquatting"""
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Common typosquatting patterns
            suspicious_patterns = [
                r'(.*)secure(.*)',
                r'(.*)login(.*)',
                r'(.*)account(.*)',
                r'(.*)bank(.*)',
                r'(.*)pay(.*)',
                r'(.*)admin(.*)'
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, domain):
                    return True
            
            # Check for character substitution patterns
            if re.search(r'[0-9]', domain):  # Numbers in domain
                return True
            
            if len(domain.split('.')) > 3:  # Too many subdomains
                return True
                
        except:
            pass
        
        return False
    
    def get_social_engineering_description(self, vuln_name: str) -> str:
        """Get detailed description of social engineering vulnerability"""
        descriptions = {
            'Login Form Without HTTPS': 'Login forms transmitted over HTTP are vulnerable to credential interception and man-in-the-middle attacks',
            'Password Field on HTTP': 'Password fields on HTTP pages expose user credentials in plaintext during transmission',
            'External Form Submissions': 'Forms submitting data to external domains could be hijacked for phishing attacks',
            'Suspicious Domain Similarity': 'Domain patterns that could indicate typosquatting or phishing domains',
            'Email Addresses in Source': 'Exposed email addresses can be harvested for spam and spear-phishing campaigns',
            'Contact Forms Exposed': 'Contact forms can be exploited for spam or social engineering attacks',
            'Mailto Links Present': 'Mailto links expose email addresses to harvesting bots',
            'Social Media Widgets': 'Social media integration can be exploited for trust-based attacks',
            'Share Buttons Present': 'Social sharing buttons can leak user behavior data',
            'Social Login Options': 'Social login can be exploited for account takeover attacks',
            'Default Credentials Hint': 'Hints about default credentials help attackers with initial access',
            'Password Recovery Weakness': 'Weak password recovery mechanisms can be exploited for account takeover',
            'Username Enumeration': 'Username enumeration helps attackers identify valid accounts',
            'Helpful Error Messages': 'Detailed error messages can leak system information to attackers',
            'HTTP Content on HTTPS Site': 'Mixed content weakens HTTPS security and trust',
            'External JavaScript Inclusion': 'External JavaScript can be compromised for supply chain attacks',
            'Mixed Content Warnings': 'Mixed content creates security vulnerabilities and user confusion',
            'Third-Party Form Actions': 'Forms submitting to third parties risk data interception'
        }
        return descriptions.get(vuln_name, 'Social engineering vulnerability that requires attention')
    
    def get_social_engineering_mitigation(self, vuln_name: str) -> str:
        """Get mitigation recommendations for social engineering vulnerabilities"""
        mitigations = {
            'Login Form Without HTTPS': 'Implement HTTPS for all authentication pages and enforce TLS encryption',
            'Password Field on HTTP': 'Migrate all sensitive forms to HTTPS and implement proper SSL/TLS',
            'External Form Submissions': 'Use relative URLs or validate external form destinations',
            'Suspicious Domain Similarity': 'Register similar domains and monitor for typosquatting attacks',
            'Email Addresses in Source': 'Use contact forms instead of exposing email addresses directly',
            'Contact Forms Exposed': 'Implement CAPTCHA and rate limiting on contact forms',
            'Mailto Links Present': 'Replace mailto links with contact forms or obfuscate email addresses',
            'Social Media Widgets': 'Review social media integrations and implement proper security headers',
            'Share Buttons Present': 'Use privacy-focused sharing solutions and inform users about data sharing',
            'Social Login Options': 'Implement additional authentication factors and monitor social login usage',
            'Default Credentials Hint': 'Remove default credential hints and force password changes',
            'Password Recovery Weakness': 'Implement secure password recovery with multi-factor authentication',
            'Username Enumeration': 'Use generic error messages for failed authentication attempts',
            'Helpful Error Messages': 'Implement generic error messages that don\'t reveal system information',
            'HTTP Content on HTTPS Site': 'Serve all content over HTTPS and implement Content Security Policy',
            'External JavaScript Inclusion': 'Use subresource integrity (SRI) for external JavaScript',
            'Mixed Content Warnings': 'Fix mixed content issues and implement strict HTTPS policies',
            'Third-Party Form Actions': 'Avoid third-party form submissions or use secure redirects'
        }
        return mitigations.get(vuln_name, 'Implement security best practices and user awareness training')

    def detect_cryptographic_vulnerabilities(self, response: requests.Response, url: str, server_info: Dict):
        """Detect exposed cryptographic signing keys and certificate vulnerabilities"""
        crypto_vulns = []
        
        # Cryptographic key exposure checks
        crypto_checks = [
            {
                'name': 'Private Key Exposed',
                'check': lambda r, u: any(key in r.text for key in ['-----BEGIN PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN DSA PRIVATE KEY-----']),
                'severity': 'critical',
                'type': 'key_exposure'
            },
            {
                'name': 'SSH Key Exposed',
                'check': lambda r, u: '-----BEGIN OPENSSH PRIVATE KEY-----' in r.text or 'ssh-rsa' in r.text,
                'severity': 'critical',
                'type': 'key_exposure'
            },
            {
                'name': 'JWT Secret Exposed',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['jwt_secret', 'jwt_key', 'json_web_token_secret']),
                'severity': 'high',
                'type': 'key_exposure'
            },
            {
                'name': 'API Signing Key Exposed',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['signing_key', 'api_signing', 'oauth_secret', 'consumer_secret']),
                'severity': 'high',
                'type': 'key_exposure'
            },
            {
                'name': 'Certificate File Exposed',
                'check': lambda r, u: '-----BEGIN CERTIFICATE-----' in r.text or '.pem' in r.text.lower(),
                'severity': 'high',
                'type': 'certificate_exposure'
            },
            {
                'name': 'Weak SSL/TLS Configuration',
                'check': lambda r, u: self.check_weak_ssl_config(response.headers),
                'severity': 'medium',
                'type': 'ssl_weakness'
            },
            {
                'name': 'Insecure Cryptographic Algorithms',
                'check': lambda r, u: any(alg in r.text.lower() for alg in ['md5', 'sha1', 'des', 'rc4']),
                'severity': 'medium',
                'type': 'weak_crypto'
            },
            {
                'name': 'Hardcoded Credentials',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['password=', 'secret=', 'api_key=', 'private_key=']),
                'severity': 'high',
                'type': 'hardcoded_secrets'
            },
            {
                'name': 'Artifact Signing Keys',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['artifact_signing', 'release_signing', 'package_signing', 'binary_signing']),
                'severity': 'critical',
                'type': 'artifact_signing'
            },
            {
                'name': 'Code Signing Certificate',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['code_signing', 'authenticode', 'apple_developer', 'android_signing']),
                'severity': 'critical',
                'type': 'code_signing'
            }
        ]
        
        # Run cryptographic vulnerability checks
        for check in crypto_checks:
            try:
                if check['check'](response, url):
                    vulnerability = {
                        'name': check['name'],
                        'severity': check['severity'],
                        'type': check['type'],
                        'url': url,
                        'description': self.get_cryptographic_description(check['name']),
                        'mitigation': self.get_cryptographic_mitigation(check['name'])
                    }
                    crypto_vulns.append(vulnerability)
                    
                    # Add to results by category
                    if check['type'] == 'key_exposure':
                        self.results['cryptographic']['key_exposure'].append(vulnerability)
                    elif check['type'] == 'certificate_exposure':
                        self.results['cryptographic']['certificate_exposure'].append(vulnerability)
                    elif check['type'] == 'ssl_weakness':
                        self.results['cryptographic']['ssl_weakness'].append(vulnerability)
                    elif check['type'] == 'weak_crypto':
                        self.results['cryptographic']['weak_crypto'].append(vulnerability)
                    elif check['type'] == 'hardcoded_secrets':
                        self.results['cryptographic']['hardcoded_secrets'].append(vulnerability)
                    elif check['type'] == 'artifact_signing':
                        self.results['cryptographic']['artifact_signing'].append(vulnerability)
                    elif check['type'] == 'code_signing':
                        self.results['cryptographic']['code_signing'].append(vulnerability)
            except:
                continue
        
        return crypto_vulns
    
    def check_weak_ssl_config(self, headers: Dict) -> bool:
        """Check for weak SSL/TLS configuration in headers"""
        try:
            # Check for insecure headers that indicate weak SSL/TLS
            insecure_indicators = [
                'sslv2',
                'sslv3',
                'tlsv1.0',
                'tlsv1.1',
                'weak cipher',
                'rc4',
                'des',
                'export'
            ]
            
            header_str = str(headers).lower()
            return any(indicator in header_str for indicator in insecure_indicators)
        except:
            return False
    
    def get_cryptographic_description(self, vuln_name: str) -> str:
        """Get detailed description of cryptographic vulnerability"""
        descriptions = {
            'Private Key Exposed': 'Private cryptographic keys are exposed in the response, allowing attackers to decrypt communications or impersonate the service',
            'SSH Key Exposed': 'SSH private keys are exposed, allowing unauthorized server access and potential lateral movement',
            'JWT Secret Exposed': 'JWT signing secrets are exposed, allowing attackers to forge authentication tokens',
            'API Signing Key Exposed': 'API signing keys are exposed, allowing attackers to forge API requests and potentially access sensitive data',
            'Certificate File Exposed': 'SSL/TLS certificates are exposed, potentially revealing server identity and enabling impersonation attacks',
            'Weak SSL/TLS Configuration': 'SSL/TLS configuration uses weak protocols or ciphers, making communications vulnerable to interception',
            'Insecure Cryptographic Algorithms': 'Deprecated cryptographic algorithms are in use, making data vulnerable to cryptographic attacks',
            'Hardcoded Credentials': 'Cryptographic credentials are hardcoded in the application, making them easily discoverable by attackers',
            'Artifact Signing Keys': 'Software artifact signing keys are exposed, allowing attackers to sign malicious code as legitimate',
            'Code Signing Certificate': 'Code signing certificates are exposed, allowing attackers to sign malware as legitimate software'
        }
        return descriptions.get(vuln_name, 'Cryptographic vulnerability that requires immediate attention')
    
    def get_cryptographic_mitigation(self, vuln_name: str) -> str:
        """Get mitigation recommendations for cryptographic vulnerabilities"""
        mitigations = {
            'Private Key Exposed': 'Immediately revoke exposed keys, generate new key pairs, and audit all systems that used the compromised keys',
            'SSH Key Exposed': 'Revoke exposed SSH keys, generate new key pairs, and update all authorized_keys files across infrastructure',
            'JWT Secret Exposed': 'Rotate JWT signing secrets immediately, invalidate all existing tokens, and implement proper secret management',
            'API Signing Key Exposed': 'Revoke exposed API keys, generate new signing keys, and implement secure key rotation policies',
            'Certificate File Exposed': 'Revoke exposed certificates, generate new certificates with new private keys, and update certificate stores',
            'Weak SSL/TLS Configuration': 'Update SSL/TLS configuration to use only TLS 1.2+ with strong cipher suites and disable weak protocols',
            'Insecure Cryptographic Algorithms': 'Replace deprecated algorithms with modern alternatives (AES, SHA-256, RSA-2048+, ECDSA)',
            'Hardcoded Credentials': 'Remove hardcoded credentials and implement secure credential management systems with proper access controls',
            'Artifact Signing Keys': 'Revoke exposed signing keys, implement secure key storage, and establish proper code signing procedures',
            'Code Signing Certificate': 'Revoke exposed certificates, implement hardware security modules (HSM) for key storage, and establish certificate lifecycle management'
        }
        return mitigations.get(vuln_name, 'Implement secure cryptographic practices and key management procedures')

    def detect_cloud_vulnerabilities(self, response: requests.Response, url: str, server_info: Dict):
        """Detect cloud infrastructure vulnerabilities and misconfigurations"""
        cloud_vulns = []
        
        # Cloud vulnerability checks
        cloud_checks = [
            {
                'name': 'AWS Credentials Exposed',
                'check': lambda r, u: any(pattern in r.text for pattern in ['AKIA', 'aws_access_key_id', 'aws_secret_access_key']),
                'severity': 'critical',
                'type': 'cloud_credentials'
            },
            {
                'name': 'Azure Credentials Exposed',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['azure_storage_key', 'azure_service_principal', 'tenant_id']),
                'severity': 'critical',
                'type': 'cloud_credentials'
            },
            {
                'name': 'Google Cloud Credentials Exposed',
                'check': lambda r, u: any(pattern in r.text for pattern in ['"private_key"', 'gcp_service_account', 'google-cloud']),
                'severity': 'critical',
                'type': 'cloud_credentials'
            },
            {
                'name': 'Cloud Storage Bucket Exposed',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['s3.amazonaws.com', 'storage.googleapis.com', 'blob.core.windows.net']),
                'severity': 'high',
                'type': 'cloud_storage'
            },
            {
                'name': 'Cloud API Keys Exposed',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['cloud_api_key', 'api_gateway_key', 'function_app_key']),
                'severity': 'high',
                'type': 'cloud_api'
            },
            {
                'name': 'Terraform State File Exposed',
                'check': lambda r, u: 'terraform.tfstate' in r.text or 'terraform_state' in r.text.lower(),
                'severity': 'critical',
                'type': 'cloud_infrastructure'
            },
            {
                'name': 'Kubernetes Config Exposed',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['kubeconfig', 'kubernetes_config', 'cluster_ca_certificate']),
                'severity': 'critical',
                'type': 'cloud_orchestration'
            },
            {
                'name': 'Docker Registry Exposed',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['docker_registry', 'container_registry', 'registry_auth']),
                'severity': 'high',
                'type': 'cloud_container'
            },
            {
                'name': 'Cloud Database Credentials',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['rds_password', 'azure_sql_password', 'cloudsql_password']),
                'severity': 'critical',
                'type': 'cloud_database'
            },
            {
                'name': 'Serverless Function Secrets',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['lambda_secret', 'function_secret', 'serverless_secret']),
                'severity': 'high',
                'type': 'cloud_serverless'
            },
            {
                'name': 'Cloud IAM Misconfiguration',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['iam_user', 'iam_role', 'administrator_access']),
                'severity': 'medium',
                'type': 'cloud_iam'
            },
            {
                'name': 'Cloud Network Exposure',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['0.0.0.0/0', 'public_subnet', 'internet_gateway']),
                'severity': 'high',
                'type': 'cloud_network'
            },
            {
                'name': 'Cloud Encryption Keys',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['kms_key', 'encryption_key', 'customer_managed_key']),
                'severity': 'critical',
                'type': 'cloud_encryption'
            },
            {
                'name': 'Cloud Logging Misconfiguration',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['disable_logging', 'no_audit', 'skip_monitoring']),
                'severity': 'medium',
                'type': 'cloud_logging'
            },
            {
                'name': 'Cloud Backup Exposure',
                'check': lambda r, u: any(pattern in r.text.lower() for pattern in ['backup_bucket', 'snapshot_public', 'backup_public']),
                'severity': 'high',
                'type': 'cloud_backup'
            }
        ]
        
        # Run cloud vulnerability checks
        for check in cloud_checks:
            try:
                if check['check'](response, url):
                    vulnerability = {
                        'name': check['name'],
                        'severity': check['severity'],
                        'type': check['type'],
                        'url': url,
                        'description': self.get_cloud_description(check['name']),
                        'mitigation': self.get_cloud_mitigation(check['name'])
                    }
                    cloud_vulns.append(vulnerability)
                    
                    # Initialize cloud results structure if not exists
                    if 'cloud' not in self.results:
                        self.results['cloud'] = {
                            'cloud_credentials': [],
                            'cloud_storage': [],
                            'cloud_api': [],
                            'cloud_infrastructure': [],
                            'cloud_orchestration': [],
                            'cloud_container': [],
                            'cloud_database': [],
                            'cloud_serverless': [],
                            'cloud_iam': [],
                            'cloud_network': [],
                            'cloud_encryption': [],
                            'cloud_logging': [],
                            'cloud_backup': []
                        }
                    
                    # Add to results by category
                    if check['type'] in self.results['cloud']:
                        self.results['cloud'][check['type']].append(vulnerability)
            except:
                continue
        
        return cloud_vulns
    
    def get_cloud_description(self, vuln_name: str) -> str:
        """Get detailed description of cloud vulnerability"""
        descriptions = {
            'AWS Credentials Exposed': 'AWS access keys and secret keys are exposed, allowing attackers to access cloud infrastructure and data',
            'Azure Credentials Exposed': 'Azure service principal credentials and storage keys are exposed, compromising cloud resources',
            'Google Cloud Credentials Exposed': 'Google Cloud service account keys and project credentials are exposed, enabling unauthorized access',
            'Cloud Storage Bucket Exposed': 'Cloud storage buckets are publicly accessible or improperly configured, exposing sensitive data',
            'Cloud API Keys Exposed': 'Cloud API gateway keys and function app keys are exposed, allowing unauthorized API access',
            'Terraform State File Exposed': 'Terraform state files containing infrastructure secrets are publicly accessible',
            'Kubernetes Config Exposed': 'Kubernetes configuration files and cluster certificates are exposed, compromising container orchestration',
            'Docker Registry Exposed': 'Container registry credentials and authentication tokens are exposed',
            'Cloud Database Credentials': 'Cloud database passwords for RDS, Azure SQL, and Cloud SQL are exposed',
            'Serverless Function Secrets': 'Serverless function environment variables and secrets are exposed in code or configuration',
            'Cloud IAM Misconfiguration': 'Identity and Access Management roles are overly permissive or misconfigured',
            'Cloud Network Exposure': 'Cloud networks are configured with overly permissive security groups or public access',
            'Cloud Encryption Keys': 'Cloud encryption keys and Key Management Service configurations are exposed',
            'Cloud Logging Misconfiguration': 'Cloud logging and audit trails are disabled or misconfigured, reducing visibility',
            'Cloud Backup Exposure': 'Cloud backups and snapshots are publicly accessible or improperly secured'
        }
        return descriptions.get(vuln_name, 'Cloud infrastructure vulnerability that requires immediate attention')
    
    def get_cloud_mitigation(self, vuln_name: str) -> str:
        """Get mitigation recommendations for cloud vulnerabilities"""
        mitigations = {
            'AWS Credentials Exposed': 'Immediately revoke exposed AWS credentials, rotate access keys, and implement IAM best practices with least privilege access',
            'Azure Credentials Exposed': 'Revoke exposed Azure credentials, rotate service principal keys, and implement Azure AD conditional access policies',
            'Google Cloud Credentials Exposed': 'Revoke exposed GCP service account keys, implement workload identity federation, and use secret manager service',
            'Cloud Storage Bucket Exposed': 'Review and restrict bucket access policies, implement bucket encryption, and enable access logging',
            'Cloud API Keys Exposed': 'Rotate exposed API keys, implement API gateway authentication, and use managed identity instead of API keys where possible',
            'Terraform State File Exposed': 'Secure Terraform state files in encrypted storage, implement state locking, and use remote state backends with access controls',
            'Kubernetes Config Exposed': 'Secure kubeconfig files, implement RBAC, rotate cluster certificates, and use managed Kubernetes services with built-in security',
            'Docker Registry Exposed': 'Rotate registry credentials, implement registry access policies, and use managed container registries with vulnerability scanning',
            'Cloud Database Credentials': 'Rotate database passwords, implement managed database services with built-in authentication, and use managed identity',
            'Serverless Function Secrets': 'Use cloud secret management services, implement environment variable encryption, and avoid hardcoding secrets in function code',
            'Cloud IAM Misconfiguration': 'Implement IAM best practices, use predefined roles instead of custom roles, and regularly audit IAM policies',
            'Cloud Network Exposure': 'Implement network segmentation, use private subnets, restrict security groups to specific IP ranges, and enable network flow logs',
            'Cloud Encryption Keys': 'Implement key rotation policies, use managed key services, enable key versioning, and implement separation of duties for key management',
            'Cloud Logging Misconfiguration': 'Enable cloud logging and monitoring services, implement log retention policies, and set up security alerting',
            'Cloud Backup Exposure': 'Encrypt backups at rest, implement backup access controls, regularly test backup restoration, and use managed backup services'
        }
        return mitigations.get(vuln_name, 'Implement cloud security best practices and regular security assessments')

    def discover_sensitive_files(self, base_url: str, protocol: str) -> List[Dict]:
        """Discover sensitive files and hidden URLs"""
        print(f"[*] Discovering sensitive files on {base_url}")

        # Common sensitive files and directories
        sensitive_paths = [
            # Configuration files
            'config.php', 'configuration.php', 'settings.php', 'config.inc.php',
            'wp-config.php', 'configuration.php', 'config.xml', 'settings.xml',
            '.env', 'config.json', 'package.json', 'composer.json',

            # Backup files
            'backup.zip', 'backup.tar.gz', 'backup.sql', 'database.sql',
            'site.zip', 'website.zip', 'public_html.zip', 'www.zip',
            'backup/', 'backups/', 'old/', 'old_site/',

            # Admin panels
            'admin/', 'administrator/', 'wp-admin/', 'admin.php',
            'login/', 'login.php', 'signin/', 'dashboard/',
            'control/', 'panel/', 'cpanel/', 'webadmin/',

            # Hidden directories
            '.git/', '.svn/', '.hg/', '.bzr/', '.cvs/',
            '.DS_Store', 'Thumbs.db', 'desktop.ini',

            # API endpoints
            'api/', 'api/v1/', 'api/v2/', 'rest/', 'graphql/',
            'swagger/', 'docs/', 'documentation/', 'api-docs/',

            # Common files
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'humans.txt', 'security.txt', '.well-known/',

            # Source code
            'source/', 'src/', 'includes/', 'lib/', 'vendor/',

            # Upload directories
            'uploads/', 'files/', 'documents/', 'media/',
            'images/', 'img/', 'photos/', 'attachments/',

            # Log files
            'error.log', 'access.log', 'debug.log', 'system.log',
            'logs/', 'log/', 'tmp/', 'temp/',

            # Database files
            'database/', 'db/', 'data/', 'mysql/', 'pgsql/',

            # Test files
            'test/', 'tests/', 'phpinfo.php', 'info.php',
            'phpmyadmin/', 'pma/', 'mysql/', 'sql/',
            
            # Cryptographic signing keys and certificates
            'private.key', 'private.pem', 'id_rsa', 'id_dsa', 'id_ecdsa',
            'server.key', 'client.key', 'cert.key', 'ssl.key',
            'certificate.pem', 'cert.pem', 'server.crt', 'client.crt',
            'ca.pem', 'ca.crt', 'ca-bundle.crt', 'intermediate.crt',
            'signing.key', 'signing.pem', 'code-signing.key',
            'jwt.key', 'jwt.pem', 'oauth.key', 'oauth.pem',
            'api.key', 'api.secret', 'secret.key', 'secrets.pem',
            '.ssh/id_rsa', '.ssh/id_dsa', '.ssh/id_ecdsa', '.ssh/id_ed25519',
            'docker.key', 'kubernetes.key', 'k8s.key',
            'artifact-signing.key', 'release-signing.key', 'package-signing.key',
            
            # Cloud Storage and Cloud Services
            # AWS S3 and Amazon Web Services
            '.aws/', '.aws/config', '.aws/credentials', '.aws/credential',
            's3-config.json', 's3-credentials.json', 'aws-credentials.json',
            'aws-access-key', 'aws-secret-key', 'aws-keys.json',
            's3-buckets.txt', 's3-buckets.json', 's3-endpoints.json',
            'cloudfront-config.json', 'route53-config.json',
            'ec2-instances.json', 'ec2-config.json', 'vpc-config.json',
            'iam-policies.json', 'iam-roles.json', 'lambda-functions.json',
            'rds-config.json', 'dynamodb-config.json',
            
            # Microsoft Azure
            '.azure/', 'azure-credentials.json', 'azure-config.json',
            'azure-access-token', 'azure-service-principal.json',
            'storage-account-keys.json', 'blob-storage-config.json',
            'container-instances.json', 'vm-config.json',
            'resource-groups.json', 'subscriptions.json',
            'active-directory-config.json', 'key-vault-secrets.json',
            
            # Google Cloud Platform
            '.gcloud/', 'gcloud-config.json', 'google-cloud-credentials.json',
            'service-account-key.json', 'service-account-keys.json',
            'gcp-project-config.json', 'bucket-config.json',
            'compute-instances.json', 'kubernetes-engine-config.json',
            'cloud-storage-config.json', 'bigquery-config.json',
            
            # Multi-cloud and General Cloud
            'cloud-config.json', 'cloud-credentials.json',
            'terraform.tfstate', 'terraform.tfvars', 'terraform-config.json',
            'pulumi-config.json', 'cloudformation-template.json',
            'arm-template.json', 'deployment-config.json',
            'kubeconfig', 'kube-config', 'kubernetes-config.json',
            'helm-values.yaml', 'helm-config.json',
            
            # Cloud APIs and Endpoints
            'cloud-api-keys.json', 'api-gateway-config.json',
            'function-apps.json', 'serverless-config.json',
            'container-registry-config.json', 'docker-registry-config.json',
            'cdn-config.json', 'load-balancer-config.json',
            
            # Cloud Security
            'cloud-security-policies.json', 'security-groups.json',
            'network-security-config.json', 'firewall-rules.json',
            'encryption-keys.json', 'key-management-config.json',
            'identity-management-config.json', 'access-policies.json'
        ]

        discovered_files = []

        for path in sensitive_paths:
            try:
                url = f"{protocol}://{base_url}/{path}"
                response = requests.head(url, timeout=self.timeout, verify=False,
                                       headers={'User-Agent': 'Lighter-Scanner/1.0'})

                if response.status_code in [200, 403, 401]:
                    discovered_files.append({
                        'path': path,
                        'url': url,
                        'status_code': response.status_code,
                        'severity': 'high' if response.status_code == 200 else 'medium',
                        'description': self.get_sensitive_file_description(path, response.status_code)
                    })
                    print(f"[+] Found sensitive file: {path} (Status: {response.status_code})")

            except requests.exceptions.RequestException:
                continue

        return discovered_files

    def discover_vulnerability_links(self, target: str, protocol: str) -> List[Dict]:
        """Discover vulnerability-related links and CVE references"""
        vuln_links = []

        # Common vulnerability paths and CVE references
        vuln_paths = [
            # Security advisories and CVE pages
            'security/', 'security/advisories/', 'vulnerabilities/', 'cve/',
            'security.txt', '.well-known/security.txt', 'security.txt',

            # Bug bounty and security pages
            'bug-bounty/', 'bounty/', 'responsible-disclosure/',
            'security-research/', 'vulnerability-disclosure/',

            # Common vulnerable endpoints
            'search?q=', 'login?redirect=', 'redirect=', 'url=', 'return=',
            'page=', 'id=', 'file=', 'path=', 'dir=', 'load=', 'include=',

            # API endpoints that might have vulnerabilities
            'api/v1/', 'api/v2/', 'rest/', 'graphql/', 'api/docs/',
            'swagger/', 'swagger-ui/', 'api/documentation/',

            # Debug and development endpoints
            'debug/', 'dev/', 'development/', 'staging/', 'test/',
            '_debug/', '_dev/', 'phpinfo/', 'info/', 'status/',

            # Common attack vectors
            'uploads/', 'file-upload/', 'upload/', 'import/', 'export/',
            'backup/', 'restore/', 'config/', 'settings/', 'preferences/'
        ]

        def check_vuln_path(path):
            try:
                url = f"{protocol}://{target}/{path}"
                response = requests.head(url, timeout=self.timeout, verify=False,
                                       headers={'User-Agent': 'Lighter-Scanner/1.0'})

                if response.status_code in [200, 403, 401, 302]:
                    # Determine vulnerability type and severity
                    vuln_type = self.classify_vulnerability_type(path)
                    severity = self.assess_vulnerability_severity(path, response.status_code)

                    return {
                        'path': path,
                        'status_code': response.status_code,
                        'vulnerability_type': vuln_type,
                        'severity': severity,
                        'potential_risk': self.get_vulnerability_risk_description(vuln_type)
                    }
            except:
                pass
            return None

        # Check vulnerability-related paths
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_vuln_path, path): path for path in vuln_paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vuln_links.append(result)

        return vuln_links

    def classify_vulnerability_type(self, path: str) -> str:
        """Classify the type of vulnerability based on the path"""
        path_lower = path.lower()

        if any(keyword in path_lower for keyword in ['search', 'q=', 'query']):
            return "injection"
        elif any(keyword in path_lower for keyword in ['redirect', 'return', 'url=', 'path=']):
            return "redirect"
        elif any(keyword in path_lower for keyword in ['upload', 'file']):
            return "file_upload"
        elif any(keyword in path_lower for keyword in ['admin', 'login', 'auth']):
            return "authentication"
        elif any(keyword in path_lower for keyword in ['debug', 'info', 'phpinfo']):
            return "information_disclosure"
        elif any(keyword in path_lower for keyword in ['api', 'graphql', 'rest']):
            return "api_exposure"
        elif any(keyword in path_lower for keyword in ['security', 'vulnerability', 'cve']):
            return "security_advisory"
        else:
            return "unknown"

    def assess_vulnerability_severity(self, path: str, status_code: int) -> str:
        """Assess the severity of a potential vulnerability"""
        path_lower = path.lower()

        # High severity vulnerabilities
        if any(keyword in path_lower for keyword in ['debug', 'phpinfo', 'config', 'settings']):
            return "high"
        elif status_code == 200 and any(keyword in path_lower for keyword in ['upload', 'admin', 'api']):
            return "high"

        # Medium severity vulnerabilities
        elif any(keyword in path_lower for keyword in ['search', 'redirect', 'login']):
            return "medium"
        elif status_code == 403:
            return "medium"

        # Low severity vulnerabilities
        else:
            return "low"

    def get_vulnerability_risk_description(self, vuln_type: str) -> str:
        """Get a description of the potential risk"""
        risk_descriptions = {
            "injection": "Potential for SQL injection or command injection attacks",
            "redirect": "Open redirect vulnerability that could be used for phishing",
            "file_upload": "Unrestricted file upload could lead to code execution",
            "authentication": "Weak authentication mechanisms or exposed admin panels",
            "information_disclosure": "Sensitive information exposure through debug endpoints",
            "api_exposure": "Exposed API endpoints that might leak sensitive data",
            "security_advisory": "Security advisory or vulnerability disclosure page",
            "unknown": "Unknown vulnerability type that requires further investigation"
        }
        return risk_descriptions.get(vuln_type, "Unknown risk type")
    
    def get_sensitive_file_description(self, path: str, status_code: int) -> str:
        """Get description for sensitive file"""
        descriptions = {
            'config': 'Configuration file that may contain sensitive information',
            'backup': 'Backup file that may contain complete website data',
            'admin': 'Admin panel or login page',
            '.git': 'Git repository exposed',
            '.env': 'Environment file with sensitive credentials',
            'api': 'API endpoint that may expose data',
            'uploads': 'Upload directory that may be accessible',
            'logs': 'Log files that may contain sensitive information',
            'database': 'Database files or directories'
        }
        
        for key in descriptions:
            if key in path.lower():
                return descriptions[key]
        
        return f'Sensitive file discovered (Status: {status_code})'

    def scan_all_services(self):
        """Perform comprehensive scan"""
        print(f"\n[*] Starting comprehensive scan on {self.target}")
        print("=" * 50)
        
        # Port scanning
        open_ports = self.scan_ports()
        
        if not open_ports:
            print("[-] No open ports found")
            return
        
        # Service detection
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for port in open_ports:
                if port in self.web_ports:
                    futures.append(executor.submit(self.detect_web_server, port))
                if port in self.email_ports:
                    futures.append(executor.submit(self.detect_email_server, port))
                if port in self.db_ports:
                    futures.append(executor.submit(self.detect_database, port))
                if port in self.app_ports:
                    futures.append(executor.submit(self.detect_cicd_platforms, port))
                    futures.append(executor.submit(self.detect_containers, port))
            
            # Collect results
            for future in as_completed(futures):
                result = future.result()
                if result:
                    if isinstance(result, dict) and 'server_type' in result:
                        if result.get('port') in self.web_ports:
                            self.results['web_servers'].append(result)
                        elif result.get('port') in self.email_ports:
                            self.results['email_servers'].append(result)
                        elif result.get('port') in self.db_ports:
                            self.results['databases'].append(result)
                    elif isinstance(result, list):
                        for item in result:
                            if 'platform' in item:
                                if item['platform'] in ['jenkins', 'gitlab', 'drone', 'travis', 'gocd']:
                                    self.results['cicd_platforms'].extend([item])
                                elif item['platform'] in ['kubernetes', 'docker', 'hadoop', 'consul', 'nomad']:
                                    self.results['containers'].extend([item])

    def generate_report(self, output_format: str = 'json') -> str:
        """Generate scan report"""
        if output_format.lower() == 'json':
            return json.dumps(self.results, indent=2, ensure_ascii=False)
        elif output_format.lower() == 'txt':
            return self.generate_text_report()
        else:
            return json.dumps(self.results, indent=2, ensure_ascii=False)

    def generate_text_report(self) -> str:
        """Generate text format report"""
        report = f"""
Lighter Security Scanner Report
===============================
Target: {self.results['target']}
Scan Time: {self.results['scan_time']}
Developer: SayerLinux (SaudiLinux1@gmail.com)

Open Ports: {', '.join(map(str, self.results['open_ports']))}

Web Servers Detected:
"""
        for server in self.results['web_servers']:
            report += f"  - {server['server_type'].title()} on port {server['port']} ({server['protocol']})\n"
            if 'frameworks' in server and server['frameworks']:
                report += f"    Frameworks: {', '.join(server['frameworks'])}\n"
            if 'cms' in server and server['cms']:
                report += f"    CMS: {', '.join(server['cms'])}\n"
            if 'vulnerabilities' in server and server['vulnerabilities']:
                for vuln in server['vulnerabilities']:
                    report += f"    Vulnerability: {vuln['name']} ({vuln['severity']})\n"
            if 'sensitive_files' in server and server['sensitive_files']:
                report += f"    Sensitive Files Discovered:\n"
                for file in server['sensitive_files']:
                    report += f"      - {file['path']} (Status: {file['status_code']}, Severity: {file['severity']})\n"
                    report += f"        {file['description']}\n"
            
            if 'social_engineering_vulnerabilities' in server and server['social_engineering_vulnerabilities']:
                report += f"    Social Engineering Vulnerabilities:\n"
                for vuln in server['social_engineering_vulnerabilities']:
                    report += f"      - {vuln['name']} ({vuln['severity']})\n"
                    report += f"        Type: {vuln['type']}\n"
                    report += f"        Description: {vuln['description']}\n"
                    report += f"        Mitigation: {vuln['mitigation']}\n"
            
            if 'cryptographic_vulnerabilities' in server and server['cryptographic_vulnerabilities']:
                report += f"    Cryptographic Vulnerabilities:\n"
                for vuln in server['cryptographic_vulnerabilities']:
                    report += f"      - {vuln['name']} ({vuln['severity']})\n"
                    report += f"        Type: {vuln['type']}\n"
                    report += f"        Description: {vuln['description']}\n"
                    report += f"        Mitigation: {vuln['mitigation']}\n"
            
            if 'cloud_vulnerabilities' in server and server['cloud_vulnerabilities']:
                report += f"    Cloud Vulnerabilities:\n"
                for vuln in server['cloud_vulnerabilities']:
                    report += f"      - {vuln['name']} ({vuln['severity']})\n"
                    report += f"        Type: {vuln['type']}\n"
                    report += f"        Description: {vuln['description']}\n"
                    report += f"        Mitigation: {vuln['mitigation']}\n"

        report += "\nEmail Servers Detected:\n"
        for server in self.results['email_servers']:
            report += f"  - {server['server_type'].title()} on port {server['port']}\n"

        report += "\nDatabases Detected:\n"
        for db in self.results['databases']:
            report += f"  - {db['server_type'].title()} on port {db['port']}\n"

        report += "\nCI/CD Platforms Detected:\n"
        for platform in self.results['cicd_platforms']:
            report += f"  - {platform['platform'].title()} on port {platform['port']}\n"

        report += "\nContainer/Orchestration Platforms:\n"
        for container in self.results['containers']:
            report += f"  - {container['platform'].title()} on port {container['port']}\n"

        # Social Engineering Summary
        if any(len(vulns) > 0 for vulns in self.results['social_engineering'].values()):
            report += "\nSocial Engineering Attack Vectors Detected:\n"
            report += "=" * 45 + "\n"
            
            for category, vulnerabilities in self.results['social_engineering'].items():
                if vulnerabilities:
                    category_title = category.replace('_', ' ').title()
                    report += f"\n{category_title}:\n"
                    for vuln in vulnerabilities:
                        report += f"  - {vuln['name']} ({vuln['severity']})\n"
                        report += f"    URL: {vuln['url']}\n"
                        report += f"    Description: {vuln['description']}\n"
                        report += f"    Mitigation: {vuln['mitigation']}\n"
        
        # Social Engineering Statistics
        total_social_vulns = sum(len(vulns) for vulns in self.results['social_engineering'].values())
        if total_social_vulns > 0:
            report += f"\nSocial Engineering Risk Assessment:\n"
            report += f"  Total Social Engineering Vulnerabilities: {total_social_vulns}\n"
            
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            for vulns in self.results['social_engineering'].values():
                for vuln in vulns:
                    severity_counts[vuln['severity']] += 1
            
            report += f"  High Severity: {severity_counts['high']}\n"
            report += f"  Medium Severity: {severity_counts['medium']}\n"
            report += f"  Low Severity: {severity_counts['low']}\n"
            
            if severity_counts['high'] > 0:
                report += f"  ⚠️  HIGH RISK: {severity_counts['high']} critical social engineering vulnerabilities detected!\n"
            elif severity_counts['medium'] > 0:
                report += f"  ⚡ MEDIUM RISK: {severity_counts['medium']} social engineering vulnerabilities require attention\n"
            else:
                report += f"  ✅ LOW RISK: Minimal social engineering vulnerabilities detected\n"

        # Cryptographic Vulnerabilities Summary
        if any(len(vulns) > 0 for vulns in self.results['cryptographic'].values()):
            report += "\nCryptographic Vulnerabilities Detected:\n"
            report += "=" * 40 + "\n"
            
            for category, vulnerabilities in self.results['cryptographic'].items():
                if vulnerabilities:
                    category_title = category.replace('_', ' ').title()
                    report += f"\n{category_title}:\n"
                    for vuln in vulnerabilities:
                        report += f"  - {vuln['name']} ({vuln['severity']})\n"
                        report += f"    URL: {vuln['url']}\n"
                        report += f"    Description: {vuln['description']}\n"
                        report += f"    Mitigation: {vuln['mitigation']}\n"
        
        # Cryptographic Risk Assessment
        total_crypto_vulns = sum(len(vulns) for vulns in self.results['cryptographic'].values())
        if total_crypto_vulns > 0:
            report += f"\nCryptographic Risk Assessment:\n"
            report += f"  Total Cryptographic Vulnerabilities: {total_crypto_vulns}\n"
            
            crypto_severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for vulns in self.results['cryptographic'].values():
                for vuln in vulns:
                    crypto_severity_counts[vuln['severity']] += 1
            
            report += f"  Critical Severity: {crypto_severity_counts['critical']}\n"
            report += f"  High Severity: {crypto_severity_counts['high']}\n"
            report += f"  Medium Severity: {crypto_severity_counts['medium']}\n"
            report += f"  Low Severity: {crypto_severity_counts['low']}\n"
            
            if crypto_severity_counts['critical'] > 0:
                report += f"  🚨 CRITICAL RISK: {crypto_severity_counts['critical']} critical cryptographic vulnerabilities detected!\n"
            elif crypto_severity_counts['high'] > 0:
                report += f"  ⚠️  HIGH RISK: {crypto_severity_counts['high']} high-severity cryptographic vulnerabilities detected!\n"
            elif crypto_severity_counts['medium'] > 0:
                report += f"  ⚡ MEDIUM RISK: {crypto_severity_counts['medium']} cryptographic vulnerabilities require attention\n"
            else:
                report += f"  ✅ LOW RISK: Minimal cryptographic vulnerabilities detected\n"
        
        # Cloud Vulnerabilities Summary
        if 'cloud' in self.results and any(len(vulns) > 0 for vulns in self.results['cloud'].values()):
            report += "\nCloud Infrastructure Vulnerabilities Detected:\n"
            report += "=" * 48 + "\n"
            
            for category, vulnerabilities in self.results['cloud'].items():
                if vulnerabilities:
                    category_title = category.replace('_', ' ').title()
                    report += f"\n{category_title}:\n"
                    for vuln in vulnerabilities:
                        report += f"  - {vuln['name']} ({vuln['severity']})\n"
                        report += f"    URL: {vuln['url']}\n"
                        report += f"    Description: {vuln['description']}\n"
                        report += f"    Mitigation: {vuln['mitigation']}\n"
        
        # Cloud Risk Assessment
        if 'cloud' in self.results:
            total_cloud_vulns = sum(len(vulns) for vulns in self.results['cloud'].values())
            if total_cloud_vulns > 0:
                report += f"\nCloud Infrastructure Risk Assessment:\n"
                report += f"  Total Cloud Vulnerabilities: {total_cloud_vulns}\n"
                
                cloud_severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                for vulns in self.results['cloud'].values():
                    for vuln in vulns:
                        cloud_severity_counts[vuln['severity']] += 1
                
                report += f"  Critical Severity: {cloud_severity_counts['critical']}\n"
                report += f"  High Severity: {cloud_severity_counts['high']}\n"
                report += f"  Medium Severity: {cloud_severity_counts['medium']}\n"
                report += f"  Low Severity: {cloud_severity_counts['low']}\n"
                
                if cloud_severity_counts['critical'] > 0:
                    report += f"  🚨 CRITICAL RISK: {cloud_severity_counts['critical']} critical cloud infrastructure vulnerabilities detected!\n"
                elif cloud_severity_counts['high'] > 0:
                    report += f"  ⚠️  HIGH RISK: {cloud_severity_counts['high']} high-severity cloud infrastructure vulnerabilities detected!\n"
                elif cloud_severity_counts['medium'] > 0:
                    report += f"  ⚡ MEDIUM RISK: {cloud_severity_counts['medium']} cloud infrastructure vulnerabilities require attention\n"
                else:
                    report += f"  ✅ LOW RISK: Minimal cloud infrastructure vulnerabilities detected\n"

        return report

def main():
    parser = argparse.ArgumentParser(
        description='Lighter - Advanced Web and Server Scanner',
        epilog='Author: SayerLinux (SaudiLinux1@gmail.com)'
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-f', '--format', choices=['json', 'txt'], default='json', help='Output format (default: json)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print("""
    __    _      _   
   / /   (_)____(_)  
  / /   / / ___/ /   
 / /___/ (__  ) /    
/_____/_/____/_/     
                      
Lighter Security Scanner v1.0
Author: SayerLinux (SaudiLinux1@gmail.com)
""")
    
    scanner = LighterScanner(args.target, args.threads, args.timeout)
    
    try:
        scanner.scan_all_services()
        
        # Generate report
        report = scanner.generate_report(args.format)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n[+] Report saved to {args.output}")
        else:
            print("\n" + "=" * 50)
            print(report)
            
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"[-] Error during scan: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())