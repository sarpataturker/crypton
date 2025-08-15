#!/bin/bash
# ===== CRYPTON macOS Setup Script =====
# Automated setup for macOS users
# Version: 5.2.0

set -e  # Exit on any error

echo "🍎 CRYPTON macOS Setup Script v5.2.0"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Functions
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_step() {
    echo -e "${CYAN}🔧 $1${NC}"
}

# Check if running on macOS
check_macos() {
    if [[ "$OSTYPE" != "darwin"* ]]; then
        print_error "This script is designed for macOS only!"
        print_info "For other platforms, use: python3 main.py"
        exit 1
    fi
    print_success "macOS detected"
}

# Check and install Homebrew
install_homebrew() {
    print_step "Checking Homebrew..."
    
    if command -v brew >/dev/null 2>&1; then
        print_success "Homebrew already installed"
    else
        print_warning "Homebrew not found. Installing..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        
        # Add Homebrew to PATH for Apple Silicon Macs
        if [[ $(uname -m) == "arm64" ]]; then
            echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
            eval "$(/opt/homebrew/bin/brew shellenv)"
        fi
        
        print_success "Homebrew installed"
    fi
}

# Check and install Python 3
install_python() {
    print_step "Checking Python 3..."
    
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_success "Python 3 found: $PYTHON_VERSION"
        
        # Check if Python version is >= 3.8
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
        
        if [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -ge 8 ]] || [[ $PYTHON_MAJOR -gt 3 ]]; then
            print_success "Python version is compatible"
        else
            print_warning "Python 3.8+ required. Installing latest Python..."
            brew install python3
        fi
    else
        print_warning "Python 3 not found. Installing..."
        brew install python3
        print_success "Python 3 installed"
    fi
}

# Check and install pip3
check_pip() {
    print_step "Checking pip3..."
    
    if command -v pip3 >/dev/null 2>&1; then
        print_success "pip3 found"
    else
        print_warning "pip3 not found. Installing..."
        python3 -m ensurepip --upgrade
        print_success "pip3 installed"
    fi
}

# Install Docker Desktop (optional)
install_docker() {
    print_step "Checking Docker..."
    
    if command -v docker >/dev/null 2>&1; then
        print_success "Docker found"
        
        # Check if Docker is running
        if docker info >/dev/null 2>&1; then
            print_success "Docker is running"
        else
            print_warning "Docker found but not running"
            print_info "Please start Docker Desktop manually"
        fi
    else
        echo ""
        print_info "Docker not found. Docker is optional but recommended for API features."
        read -p "🐳 Install Docker Desktop? (y/n): " -n 1 -r
        echo ""
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_step "Installing Docker Desktop..."
            brew install --cask docker
            print_success "Docker Desktop installed"
            print_warning "Please launch Docker Desktop from Applications folder"
        else
            print_info "Skipping Docker installation"
        fi
    fi
}

# Create virtual environment
create_venv() {
    print_step "Setting up virtual environment..."
    
    if [[ -d "venv" ]]; then
        print_info "Virtual environment already exists"
    else
        python3 -m venv venv
        print_success "Virtual environment created"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    print_success "Virtual environment activated"
    
    # Upgrade pip inside venv
    pip install --upgrade pip
    print_success "pip upgraded"
}

# Install Python dependencies
install_dependencies() {
    print_step "Installing Python dependencies..."
    
    # Install terminal app dependencies
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
        print_success "Terminal app dependencies installed"
    else
        print_warning "requirements.txt not found"
    fi
    
    # Ask about API dependencies
    echo ""
    print_info "API dependencies are optional but enable REST API features"
    read -p "🌐 Install API server dependencies? (y/n): " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [[ -f "api_requirements.txt" ]]; then
            pip install -r api_requirements.txt
            print_success "API dependencies installed"
        else
            print_warning "api_requirements.txt not found"
        fi
    else
        print_info "Skipping API dependencies"
    fi
}

# Create .env file
setup_env() {
    print_step "Setting up environment configuration..."
    
    if [[ -f ".env" ]]; then
        print_info ".env file already exists"
    else
        if [[ -f ".env.example" ]]; then
            cp .env.example .env
            print_success ".env file created from template"
            print_warning "Please edit .env file with your settings"
        else
            print_warning ".env.example not found, creating basic .env"
            cat > .env << EOF
# CRYPTON Environment Configuration
CRYPTON_SECRET_KEY=change-this-secret-key-in-production
ENVIRONMENT=development
HOST=0.0.0.0
PORT=8000
EOF
            print_success "Basic .env file created"
        fi
    fi
}

# Test installation
test_installation() {
    print_step "Testing installation..."
    
    echo ""
    print_info "Testing Python imports..."
    
    python3 -c "
import sys
import importlib

packages = ['cryptography', 'colorama', 'bcrypt', 'argon2', 'nacl', 'passlib']
failed = []

for pkg in packages:
    try:
        if pkg == 'argon2':
            importlib.import_module(pkg)
        else:
            importlib.import_module(pkg)
        print(f'✅ {pkg}')
    except ImportError:
        print(f'❌ {pkg}')
        failed.append(pkg)

if failed:
    print(f'\\n⚠️  Failed imports: {failed}')
    sys.exit(1)
else:
    print('\\n🎉 All core packages imported successfully!')
"
    
    if [[ $? -eq 0 ]]; then
        print_success "Installation test passed!"
    else
        print_error "Installation test failed!"
        exit 1
    fi
}

# Create launcher scripts
create_launchers() {
    print_step "Creating launcher scripts..."
    
    # Terminal app launcher
    cat > run_crypton.sh << 'EOF'
#!/bin/bash
# CRYPTON Terminal App Launcher
cd "$(dirname "$0")"
source venv/bin/activate 2>/dev/null || true
python3 main.py "$@"
EOF
    chmod +x run_crypton.sh
    print_success "Created run_crypton.sh"
    
    # API server launcher
    cat > run_api.sh << 'EOF'
#!/bin/bash
# CRYPTON API Server Launcher
cd "$(dirname "$0")"
source venv/bin/activate 2>/dev/null || true
python3 api_server.py "$@"
EOF
    chmod +x run_api.sh
    print_success "Created run_api.sh"
}

# Main setup function
main() {
    echo "Starting CRYPTON setup for macOS..."
    echo ""
    
    # Check prerequisites
    check_macos
    
    # Install dependencies
    install_homebrew
    install_python
    check_pip
    
    # Optional components
    install_docker
    
    # Setup Python environment
    create_venv
    install_dependencies
    
    # Configuration
    setup_env
    
    # Create launchers
    create_launchers
    
    # Test everything
    test_installation
    
    echo ""
    echo "🎉 CRYPTON Setup Complete!"
    echo "=========================="
    echo ""
    print_success "Installation successful!"
    echo ""
    print_info "To run CRYPTON terminal app:"
    echo "  ./run_crypton.sh"
    echo "  or: source venv/bin/activate && python3 main.py"
    echo ""
    print_info "To run CRYPTON API server:"
    echo "  ./run_api.sh"
    echo "  or: source venv/bin/activate && python3 api_server.py"
    echo ""
    print_info "To test Docker integration:"
    echo "  ./run_crypton.sh  (then select Docker Manager)"
    echo ""
    print_warning "Don't forget to:"
    echo "  1. Edit .env file with your settings"
    echo "  2. Start Docker Desktop (if using API features)"
    echo "  3. Review the README.md for detailed instructions"
    echo ""
    print_info "Happy encrypting! 🔐"
}

# Handle Ctrl+C
trap 'echo -e "\n\n⚠️  Setup interrupted by user. Run again to continue."; exit 1' INT

# Run main function
main "$@"