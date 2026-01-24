#!/usr/bin/env bash
# install.sh - Cross-platform installation script for Marvain voice agent
# Supports: macOS, Ubuntu Linux, and other Debian-based systems

set -euo pipefail

# Color codes
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Darwin*)    echo "macos" ;;
        Linux*)
            if [ -f /etc/os-release ]; then
                # shellcheck disable=SC1091
                . /etc/os-release
                case "$ID" in
                    ubuntu|debian|linuxmint|pop) echo "debian" ;;
                    fedora|rhel|centos|rocky|alma) echo "redhat" ;;
                    arch|manjaro) echo "arch" ;;
                    *) echo "linux" ;;
                esac
            else
                echo "linux"
            fi
            ;;
        *)          echo "unknown" ;;
    esac
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Find Python 3.9+
find_python() {
    for cmd in python3.12 python3.11 python3.10 python3 python; do
        if command_exists "$cmd"; then
            local version major minor
            version=$("$cmd" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
            major=$(echo "$version" | cut -d. -f1)
            minor=$(echo "$version" | cut -d. -f2)
            if [ "$major" -eq 3 ] && [ "$minor" -ge 9 ]; then
                echo "$cmd"
                return 0
            fi
        fi
    done
    return 1
}

# Install system dependencies based on OS
install_system_deps() {
    local os_type="$1"

    log_info "Installing system dependencies for $os_type..."

    case "$os_type" in
        macos)
            if ! command_exists brew; then
                log_warn "Homebrew not installed. Please install it from https://brew.sh"
                return 1
            fi

            # Install dependencies via Homebrew
            local brew_deps=(python@3.12 ffmpeg awscli)
            for dep in "${brew_deps[@]}"; do
                if ! brew list "$dep" &>/dev/null; then
                    log_info "Installing $dep..."
                    brew install "$dep"
                fi
            done

            # Install SAM CLI
            if ! command_exists sam; then
                log_info "Installing AWS SAM CLI..."
                brew install aws-sam-cli
            fi
            ;;

        debian)
            log_info "Updating apt package list..."
            sudo apt-get update -qq

            # Install system packages
            local apt_deps=(python3 python3-pip python3-venv python3-dev ffmpeg curl unzip)
            for dep in "${apt_deps[@]}"; do
                if ! dpkg -l "$dep" &>/dev/null; then
                    log_info "Installing $dep..."
                    sudo apt-get install -y -qq "$dep"
                fi
            done

            # Install AWS CLI v2
            if ! command_exists aws; then
                log_info "Installing AWS CLI..."
                curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
                unzip -q /tmp/awscliv2.zip -d /tmp
                sudo /tmp/aws/install
                rm -rf /tmp/awscliv2.zip /tmp/aws
            fi

            # Install SAM CLI
            if ! command_exists sam; then
                log_info "Installing AWS SAM CLI..."
                pip3 install --user aws-sam-cli
            fi
            ;;

        redhat)
            log_info "Updating dnf package list..."
            sudo dnf check-update || true

            local dnf_deps=(python3 python3-pip python3-devel ffmpeg curl unzip)
            for dep in "${dnf_deps[@]}"; do
                if ! rpm -q "$dep" &>/dev/null; then
                    log_info "Installing $dep..."
                    sudo dnf install -y "$dep"
                fi
            done

            # AWS CLI and SAM similar to debian
            if ! command_exists aws; then
                curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
                unzip -q /tmp/awscliv2.zip -d /tmp
                sudo /tmp/aws/install
                rm -rf /tmp/awscliv2.zip /tmp/aws
            fi

            if ! command_exists sam; then
                pip3 install --user aws-sam-cli
            fi
            ;;

        arch)
            sudo pacman -Sy --noconfirm python python-pip ffmpeg aws-cli-v2 || true
            pip install --user aws-sam-cli
            ;;

        *)
            log_warn "Unknown OS type. Please install dependencies manually."
            log_info "Required: Python 3.9+, pip, ffmpeg, AWS CLI, SAM CLI"
            ;;
    esac

    log_success "System dependencies installed"
}

# Create and setup Python virtual environment
setup_venv() {
    local python_cmd="$1"
    local venv_dir="${2:-.venv}"

    if [ ! -d "$venv_dir" ]; then
        log_info "Creating Python virtual environment..."
        "$python_cmd" -m venv "$venv_dir"
    fi

    # Activate venv
    # shellcheck disable=SC1091
    source "$venv_dir/bin/activate"

    # Upgrade pip
    log_info "Upgrading pip..."
    pip install --quiet --upgrade pip setuptools wheel

    # Install requirements
    if [ -f "requirements.txt" ]; then
        log_info "Installing Python dependencies..."
        pip install --quiet -r requirements.txt
    fi

    log_success "Python environment configured"
}

# Verify installation
verify_installation() {
    local status=0

    log_info "Verifying installation..."

    # Check Python
    if python3 --version &>/dev/null; then
        log_success "Python: $(python3 --version)"
    else
        log_error "Python not found"
        status=1
    fi

    # Check AWS CLI
    if command_exists aws; then
        log_success "AWS CLI: $(aws --version | head -1)"
    else
        log_error "AWS CLI not found"
        status=1
    fi

    # Check SAM CLI
    if command_exists sam; then
        log_success "SAM CLI: $(sam --version)"
    else
        log_warn "SAM CLI not found (needed for deployments)"
    fi

    # Check ffmpeg
    if command_exists ffmpeg; then
        log_success "ffmpeg: $(ffmpeg -version 2>&1 | head -1)"
    else
        log_warn "ffmpeg not found (optional, for audio processing)"
    fi

    return $status
}

# Print usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Cross-platform installation script for Marvain voice agent.

OPTIONS:
    -h, --help          Show this help message
    --skip-system       Skip system dependency installation
    --skip-venv         Skip Python virtual environment setup
    --venv-dir DIR      Virtual environment directory (default: .venv)

EXAMPLES:
    $0                  # Full installation
    $0 --skip-system    # Only setup Python environment
    $0 --venv-dir venv  # Use 'venv' directory for virtual environment

SUPPORTED PLATFORMS:
    - macOS (via Homebrew)
    - Ubuntu/Debian Linux
    - RHEL/Fedora/CentOS
    - Arch Linux

EOF
}

# Parse arguments
parse_args() {
    SKIP_SYSTEM=false
    SKIP_VENV=false
    VENV_DIR=".venv"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            --skip-system)
                SKIP_SYSTEM=true
                shift
                ;;
            --skip-venv)
                SKIP_VENV=true
                shift
                ;;
            --venv-dir)
                VENV_DIR="$2"
                shift 2
                ;;
            --venv-dir=*)
                VENV_DIR="${1#*=}"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Main function
main() {
    if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
        log_error "This script must be executed directly, not sourced."
        return 1
    fi

    parse_args "$@"

    echo ""
    log_info "=== Marvain Voice Agent Installation ==="
    echo ""

    # Detect OS
    local os_type
    os_type=$(detect_os)
    log_info "Detected OS: $os_type"

    # Change to script directory
    cd "$(dirname "${BASH_SOURCE[0]}")/.."

    # Install system dependencies
    if [ "$SKIP_SYSTEM" = false ]; then
        install_system_deps "$os_type"
    else
        log_info "Skipping system dependency installation"
    fi

    # Find Python
    local python_cmd
    python_cmd=$(find_python) || {
        log_error "Python 3.9+ not found. Please install Python first."
        exit 1
    }
    log_success "Found Python: $python_cmd"

    # Setup virtual environment
    if [ "$SKIP_VENV" = false ]; then
        setup_venv "$python_cmd" "$VENV_DIR"
    else
        log_info "Skipping virtual environment setup"
    fi

    echo ""
    verify_installation

    echo ""
    log_success "=== Installation Complete ==="
    echo ""
    log_info "Next steps:"
    echo "  1. Source the initialization script:"
    echo "     source initwyw <AWS_PROFILE> <AWS_REGION>"
    echo ""
    echo "  2. Start the GUI server:"
    echo "     python -m uvicorn client.gui:app --reload"
    echo ""
}

main "$@"