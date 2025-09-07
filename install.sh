#!/bin/bash
# EthicalRecon Installation Script
# Automated setup for Kali Linux and other penetration testing environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "    ███████╗████████╗██╗  ██╗██╗ ██████╗ █████╗ ██╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
echo "    ██╔════╝╚══██╔══╝██║  ██║██║██╔════╝██╔══██╗██║     ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
echo "    █████╗     ██║   ███████║██║██║     ███████║██║     ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
echo "    ██╔══╝     ██║   ██╔══██║██║██║     ██╔══██║██║     ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
echo "    ███████╗   ██║   ██║  ██║██║╚██████╗██║  ██║███████╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
echo "    ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
echo -e "${NC}"
echo -e "${YELLOW}🎯 Comprehensive Ethical Hacking Reconnaissance Toolkit v2.0.0${NC}"
echo -e "${GREEN}⚡ Installation Script for Authorized Security Testing${NC}"
echo -e "${PURPLE}🛡️  For authorized security testing and bug bounty research only${NC}"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${YELLOW}[WARNING]${NC} Running as root. Consider using a regular user account."
   read -p "Continue anyway? (y/N): " -n 1 -r
   echo
   if [[ ! $REPLY =~ ^[Yy]$ ]]; then
       exit 1
   fi
fi

# Function to print status messages
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check OS
print_status "Detecting operating system..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v apt &> /dev/null; then
        OS="debian"
        print_success "Debian/Ubuntu-based system detected"
    elif command -v yum &> /dev/null; then
        OS="redhat"
        print_success "RedHat/CentOS-based system detected"
    elif command -v pacman &> /dev/null; then
        OS="arch"
        print_success "Arch Linux detected"
    else
        OS="unknown"
        print_warning "Unknown Linux distribution"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    print_success "macOS detected"
else
    OS="unknown"
    print_warning "Unknown operating system"
fi

# Check Python version
print_status "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3,8) else 1)'; then
        print_success "Python $PYTHON_VERSION detected (✓)"
    else
        print_error "Python 3.8+ required, found $PYTHON_VERSION"
        exit 1
    fi
else
    print_error "Python 3 not found. Please install Python 3.8+ first."
    exit 1
fi

# Check pip
print_status "Checking pip installation..."
if command -v pip3 &> /dev/null; then
    print_success "pip3 found"
    PIP_CMD="pip3"
elif command -v pip &> /dev/null && pip --version | grep -q "python 3"; then
    print_success "pip found (Python 3)"
    PIP_CMD="pip"
else
    print_error "pip for Python 3 not found"
    print_status "Installing pip..."
    
    if [[ "$OS" == "debian" ]]; then
        sudo apt update && sudo apt install -y python3-pip
    elif [[ "$OS" == "redhat" ]]; then
        sudo yum install -y python3-pip
    elif [[ "$OS" == "arch" ]]; then
        sudo pacman -S python-pip
    elif [[ "$OS" == "macos" ]]; then
        print_error "Please install pip manually: curl https://bootstrap.pypa.io/get-pip.py | python3"
        exit 1
    fi
    
    PIP_CMD="pip3"
fi

# Install system dependencies
print_status "Installing system dependencies..."
case "$OS" in
    "debian")
        sudo apt update
        sudo apt install -y curl wget git build-essential python3-dev
        ;;
    "redhat")
        sudo yum groupinstall -y "Development Tools"
        sudo yum install -y curl wget git python3-devel
        ;;
    "arch")
        sudo pacman -S curl wget git base-devel python
        ;;
    "macos")
        if ! command -v brew &> /dev/null; then
            print_warning "Homebrew not found. Install manually if needed."
        else
            brew install curl wget git
        fi
        ;;
esac

# Create virtual environment (recommended)
print_status "Setting up Python virtual environment..."
if [[ ! -d "venv" ]]; then
    python3 -m venv venv
    print_success "Virtual environment created"
else
    print_success "Virtual environment already exists"
fi

# Activate virtual environment
print_status "Activating virtual environment..."
source venv/bin/activate
print_success "Virtual environment activated"

# Upgrade pip
print_status "Upgrading pip..."
$PIP_CMD install --upgrade pip

# Install Python dependencies
print_status "Installing Python dependencies..."
if [[ -f "requirements.txt" ]]; then
    $PIP_CMD install -r requirements.txt
    print_success "Dependencies installed from requirements.txt"
else
    print_status "requirements.txt not found, installing core dependencies..."
    $PIP_CMD install requests colorama urllib3 PyYAML
    print_success "Core dependencies installed"
fi

# Make script executable
print_status "Setting up executable permissions..."
chmod +x ethicalrecon.py
print_success "Script permissions set"

# Create symlink for global access (optional)
read -p "Create global symlink for 'ethicalrecon' command? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    INSTALL_DIR="/usr/local/bin"
    if [[ -w "$INSTALL_DIR" ]]; then
        ln -sf "$(pwd)/ethicalrecon.py" "$INSTALL_DIR/ethicalrecon"
        print_success "Global symlink created: $INSTALL_DIR/ethicalrecon"
    else
        sudo ln -sf "$(pwd)/ethicalrecon.py" "$INSTALL_DIR/ethicalrecon"
        print_success "Global symlink created: $INSTALL_DIR/ethicalrecon (with sudo)"
    fi
fi

# Create directories
print_status "Creating directory structure..."
mkdir -p results
mkdir -p wordlists
mkdir -p templates
print_success "Directory structure created"

# Download additional wordlists (optional)
read -p "Download additional wordlists? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Downloading SecLists wordlists..."
    if [[ ! -d "wordlists/SecLists" ]]; then
        git clone https://github.com/danielmiessler/SecLists.git wordlists/SecLists
        print_success "SecLists downloaded"
    else
        print_success "SecLists already exists"
    fi
    
    print_status "Downloading common wordlists..."
    cd wordlists
    
    # Common directories
    if [[ ! -f "common-directories.txt" ]]; then
        curl -s https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt -o common-directories.txt
        print_success "Common directories wordlist downloaded"
    fi
    
    # Common files
    if [[ ! -f "common-files.txt" ]]; then
        curl -s https://raw.githubusercontent.com/digination/dirbuster-ng/master/wordlists/vulns/test.txt -o common-files.txt
        print_success "Common files wordlist downloaded"
    fi
    
    cd ..
fi

# Run basic test
print_status "Running basic functionality test..."
if python3 ethicalrecon.py --help &> /dev/null; then
    print_success "Basic functionality test passed"
else
    print_error "Basic functionality test failed"
    exit 1
fi

# Security reminder
echo ""
echo -e "${PURPLE}=====================================================================${NC}"
echo -e "${PURPLE}                        IMPORTANT SECURITY NOTICE${NC}"
echo -e "${PURPLE}=====================================================================${NC}"
echo -e "${RED}This tool is for AUTHORIZED SECURITY TESTING ONLY${NC}"
echo ""
echo -e "${YELLOW}Before using EthicalRecon:${NC}"
echo -e "• Obtain explicit written permission from system owners"
echo -e "• Only test systems you own or have authorization to test"
echo -e "• Comply with all applicable laws and regulations"
echo -e "• Use responsibly and ethically"
echo -e "• Do not use for illegal activities"
echo ""
echo -e "${GREEN}The developers are not responsible for any misuse of this tool.${NC}"
echo -e "${PURPLE}=====================================================================${NC}"
echo ""

# Installation complete
print_success "EthicalRecon installation completed successfully!"
echo ""
echo -e "${CYAN}Quick Start:${NC}"
echo -e "  ${GREEN}# Activate virtual environment${NC}"
echo -e "  source venv/bin/activate"
echo ""
echo -e "  ${GREEN}# Scan URLs from file (httpx output)${NC}"
echo -e "  python3 ethicalrecon.py -f live_hosts.txt -o results"
echo ""
echo -e "  ${GREEN}# Scan single URL${NC}"
echo -e "  python3 ethicalrecon.py -u 'http://example.com/search?q=test' -o single_scan"
echo ""
echo -e "  ${GREEN}# Advanced scan with custom settings${NC}"
echo -e "  python3 ethicalrecon.py -f subdomains.txt -t 20 --format html,json --timeout 15"
echo ""
echo -e "${CYAN}Documentation:${NC}"
echo -e "  python3 ethicalrecon.py --help"
echo ""
echo -e "${YELLOW}Remember: Always ensure you have permission before scanning!${NC}"
