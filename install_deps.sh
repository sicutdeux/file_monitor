#!/bin/bash
set -e

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

# Function to check for interactive dpkg/apt process
check_package_manager_status() {
    # Check if there's an apt/dpkg process running
    if pgrep -f "apt|dpkg" > /dev/null; then
        echo "A package management process is already running."
        
        # Check if it might be waiting for input
        if ps aux | grep -E 'apt|dpkg' | grep -v grep | grep -q 'S'; then
            echo "=============================================================="
            echo "It appears that a package management process is waiting for input."
            echo "This could be a GUI prompt asking to restart services or confirm changes."
            echo ""
            echo "Please:"
            echo "1. Look for any package manager windows or terminal prompts"
            echo "2. Complete those operations first"
            echo "3. Then run this script again"
            echo "=============================================================="
        else
            echo "Please wait for it to complete before running this script."
        fi
        return 1
    fi
    return 0
}

# Check if package manager is running before proceeding
if ! check_package_manager_status; then
    exit 1
fi

# Note: System dependencies like python3-pip are now handled as package dependencies
# in the Debian control file, not installed here

echo "Installing required Python packages..."
pip3 install python-telegram-bot==20.8 watchdog==3.0.0 colorama==0.4.6 python-dotenv==1.0.0

echo "Dependencies installed successfully."
