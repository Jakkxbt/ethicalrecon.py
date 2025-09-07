# ethicalrecon.py
recon tool
🎯 Comprehensive Ethical Hacking Reconnaissance Toolkit v2.0.0
⚡ Multi-threaded vulnerability scanning with PoC verification
🔍 Subdomain enumeration → httpx → deep vulnerability analysis workflow
🛡️ For authorized security testing and bug bounty research only
Overview

EthicalRecon is a professional-grade vulnerability scanner designed specifically for ethical hackers, penetration testers, and bug bounty researchers. Built to integrate seamlessly with the popular subdomain enumeration → httpx → vulnerability scanning workflow, it provides comprehensive security testing with advanced PoC verification to eliminate false positives.
Key Features
🚀 Advanced Vulnerability Detection

    Cross-Site Scripting (XSS) - Context-aware detection with JavaScript execution verification
    SQL Injection - Time-based, error-based, and union-based detection with database fingerprinting
    Local File Inclusion (LFI) - File signature verification and wrapper exploitation
    Remote Code Execution (RCE) - Command execution verification with unique markers
    Server-Side Request Forgery (SSRF) - Cloud metadata and internal service testing
    Open Redirects - External domain redirection verification

🎯 Proof-of-Concept Verification

    Real-time PoC generation for each vulnerability found
    False positive reduction through advanced verification techniques
    Execution proof displayed in terminal for immediate validation
    Ready-to-use exploit commands for security reporting

⚡ Performance & Integration

    Multi-threaded scanning with configurable thread pools
    httpx output compatibility - Direct integration with subdomain enumeration workflows
    URL parameter handling - Robust parsing of complex URLs with multiple parameters
    Rate limiting and respectful scanning practices

📊 Comprehensive Reporting

    Multiple output formats: JSON, HTML, and text reports
    Executive summaries with vulnerability statistics
    Technical details with CVSS scoring and OWASP mapping
    Curl commands and remediation advice included

Installation
Quick Install (Recommended)

# Clone the repository
git clone https://github.com/yourusername/ethicalrecon.git
cd ethicalrecon

# Run the automated installer
chmod +x install.sh
./install.sh

Manual Installation

# Ensure Python 3.8+ is installed
python3 --version

# Install dependencies
pip3 install -r requirements.txt

# Make script executable
chmod +x ethicalrecon.py

Usage
Basic Examples
Scan URLs from httpx output file

python3 ethicalrecon.py -f live_hosts.txt -o results

Scan a single URL

python3 ethicalrecon.py -u "http://example.com/search?q=test" -o single_scan

Advanced scanning with custom settings

python3 ethicalrecon.py -f httpx_output.txt -t 20 --format html,json --timeout 15

Workflow Integration

EthicalRecon is designed to integrate perfectly with your existing reconnaissance workflow:

# 1. Subdomain enumeration
subfinder -d target.com -silent | httpx -silent > live_hosts.txt

# 2. Vulnerability scanning with EthicalRecon
python3 ethicalrecon.py -f live_hosts.txt -o vulnerability_scan

# 3. Review results
ls vulnerability_scan/

Command Line Options

Input Options:
  -f, --file        File containing URLs to scan (one per line)
  -u, --url         Single URL to scan

Output Options:
  -o, --output      Output directory for results (default: ethicalrecon_results)
  --format          Output formats: json,html,text (default: json,text)

Scanning Options:
  -t, --threads     Number of threads (default: 10)
  --timeout         Request timeout in seconds (default: 10)
  --user-agent      Custom User-Agent string
  --scan-types      Vulnerability types: xss,sqli,lfi,rce,ssrf,redirect (default: all)

Utility Options:
  --no-banner       Suppress banner output
  -v, --verbose     Verbose output
  --help            Show help message

Configuration

EthicalRecon supports advanced configuration through the config.yaml file:

scanning:
  threads: 10
  timeout: 10
  delay: 0.1
  verify_ssl: false

detection:
  enabled_types:
    - xss
    - sqli
    - lfi
    - rce
    - ssrf
    - redirect
  confidence_threshold: 0.5
  deep_scan: true

output:
  formats:
    - json
    - html
    - text
  include_poc: true

Example Output
Terminal Output

[SCANNING] http://example.com/search.php?q=test
  Testing parameter: q
[XSS FOUND] http://example.com/search.php?q=test - Parameter: q
[POC] Payload '<script>alert('XSS')</script>' reflected in executable context

[SUMMARY] Vulnerabilities by severity:
  Critical: 1
  High: 2
  Medium: 1

[COMPLETED] Scan finished. Reports saved to results/

Generated Reports

    JSON Report: Machine-readable format for automation
    HTML Report: Professional presentation with executive summary
    Text Report: Human-readable format for documentation

Security Features
Responsible Scanning

    Rate limiting to avoid overwhelming target servers
    Respectful delays between requests
    SSL verification bypass for testing environments
    User-agent customization for transparency

PoC Verification

    Context-aware XSS detection - Verifies actual JavaScript execution
    Time-based SQL injection - Statistical analysis of response delays
    File signature verification - Confirms successful file inclusion
    Command execution proof - Unique markers verify RCE

File Structure

ethicalrecon/
├── ethicalrecon.py          # Main scanner script
├── config.yaml              # Configuration file
├── requirements.txt         # Python dependencies
├── install.sh              # Automated installer
├── setup.py                # Python package setup
├── LICENSE                 # MIT license
├── README.md               # This file
├── payloads/               # Vulnerability payloads
│   ├── xss_payloads.txt
│   ├── sqli_payloads.txt
│   └── lfi_payloads.txt
├── results/                # Scan results directory
└── test_urls.txt           # Sample test URLs

Requirements

    Python 3.8+
    requests - HTTP client library
    colorama - Terminal colors
    urllib3 - URL parsing
    PyYAML - Configuration parsing
    virtual enviornment (venv)

Legal Disclaimer

FOR AUTHORIZED SECURITY TESTING ONLY

This tool is intended for authorized security testing, penetration testing, and bug bounty research. Users must:

    ✅ Obtain explicit written permission before testing any systems
    ✅ Only test systems you own or have explicit authorization to test
    ✅ Comply with all applicable local, state, and federal laws
    ✅ Use the tool responsibly and ethically
    ❌ Not use this tool for any illegal activities

The developers and contributors:

    Do not condone or support any illegal activities
    Are not responsible for any misuse of this software
    Disclaim all liability for any damages caused by improper use
    Provide this software for educational and authorized testing purposes only

Contributing

Contributions are welcome! Please read our contributing guidelines and ensure all contributions are for legitimate security research purposes.

    Fork the repository
    Create a feature branch
    Make your changes
    Add tests if applicable
    Submit a pull request

Support

    Documentation: Check the GitHub Wiki
    Issues: Report bugs or request features through GitHub Issues
    Security: Report security issues responsibly

Acknowledgments

    OWASP - For vulnerability classification standards

    IF YOU HAVE ISSUES INSTALLING, DOWNLOAD THE ZIP FILES
    Security Community - For payload research and techniques
    Bug Bounty Platforms - For real-world testing methodologies

License

MIT License - See LICENSE file for details.
