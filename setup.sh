#!/bin/bash

# ─────────────────────────────────────────────────────────────────
# WEB-CRAWLER INSTALLER v1.0
# Author: CYBER-MRINAL
# Description: Installs all dependencies and sets up the web crawler
# ─────────────────────────────────────────────────────────────────

set -e

SCRIPT_NAME="web-crawler.py"
GIT=".git"
PATH_GIT="/usr/local/bin"
INSTALL_NAME="web-crawler"
INSTALL_PATH="/usr/local/bin/$INSTALL_NAME"
LOG_FILE="/var/log/web-crawler-setup.log"
REQUIRED_CMDS=("git" "python3")

# ─────────────────────────────────────────────────────────────────

log() {
    echo "[$(date +'%F %T')] $1" | tee -a "$LOG_FILE"
}

# ─────────────────────────────────────────────────────────────────
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

# ─────────────────────────────────────────────────────────────────
install_missing_packages() {
    distro=$(detect_distro)
    echo -e "\033[1;31m"
    log " >> Detected distro: $distro"
    echo ""
    echo -e "\033[0m"

    case "$distro" in
        kali|debian|ubuntu|parrot)
            PKG_INSTALL="sudo apt-get install -y"
            sudo apt-get update
            ;;
        arch|manjaro|artix|athenaos|garuda)
            PKG_INSTALL="sudo pacman -S --noconfirm"
            sudo pacman -Sy
            ;;
        *)
            echo " >> ❌ Unsupported distro: $distro"
            log " >> Unsupported distro: $distro"
            exit 1
            ;;
    esac

    for cmd in "${REQUIRED_CMDS[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log " >> Installing missing dependency: $cmd"
            $PKG_INSTALL "$cmd"
        else
            log " >> Dependency already installed: $cmd"
        fi
    done
}

# ─────────────────────────────────────────────────────────────────
validate_script() {
    if [[ ! -f "$SCRIPT_NAME" ]]; then
        echo -e "\033[1;31m"
        echo "❌ Cannot find $SCRIPT_NAME in the current directory."
        log "Script missing: $SCRIPT_NAME"
        echo -e "\033[0m"
        exit 1
    fi
    chmod +x "$SCRIPT_NAME"
    log "$SCRIPT_NAME made executable."
}

# ─────────────────────────────────────────────────────────────────
install_system_wide() {
    sudo cp "$SCRIPT_NAME" "$INSTALL_PATH"
    sudo chmod +x "$INSTALL_PATH"
    log "->> Installed as system command: $INSTALL_NAME"
    echo "->> ✅ Tool is now available as: $INSTALL_NAME"
}

# ─────────────────────────────────────────────────────────────────
main() {
    echo -e "\033[1;33m"
    echo "    🔧 Setting up WEB-CRAWLER tool..."
    log "<==== SETUP START ====>"
    echo -e "\033[0m"

    install_missing_packages
    validate_script

    echo ""
    echo -e "\033[1;33m"
    read -rp "➡️  Install system-wide as '$INSTALL_NAME'? [y/N]: " choice
    case "$choice" in
        y|Y) install_system_wide ;;
        *) echo "ℹ️  Skipped system-wide install. Use ./crawler.py to run." ;;
    esac
    echo -e "\033[0m"
    
    echo -e "\033[1;33m"
    echo "      ✅ Setup complete for WEB-CRAWLER...."
    log "<==== SETUP COMPLETE ====>"
    echo -e "\033[0m"
}

main

