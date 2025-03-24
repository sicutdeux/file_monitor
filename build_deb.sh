#!/bin/bash
set -e

PACKAGE_NAME="file-monitor"
VERSION="1.3.0"
PACKAGE_DIR="$PACKAGE_NAME-$VERSION"

# Check for required build dependencies
if ! command -v dpkg-deb &> /dev/null; then
    echo "dpkg-deb command not found. Installing build dependencies..."
    if [ "$EUID" -ne 0 ]; then
        echo "Please run this script with sudo to install build dependencies."
        exit 1
    fi
    apt update
    apt install -y build-essential debhelper dh-python
fi

# Install Python dependencies (optional, uncomment if you want to install dependencies during build)
# if [ "$EUID" -eq 0 ]; then
#    echo "Installing Python dependencies..."
#    apt install -y python3-pip
#    pip3 install python-telegram-bot==20.8 watchdog==3.0.0 colorama==0.4.6 python-dotenv==1.0.0
# else
#    echo "Skipping Python dependencies installation (not running as root)"
# fi

# Create package structure
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR/DEBIAN"
mkdir -p "$PACKAGE_DIR/usr/lib/file_monitor"
mkdir -p "$PACKAGE_DIR/etc/file_monitor"
mkdir -p "$PACKAGE_DIR/lib/systemd/system"
mkdir -p "$PACKAGE_DIR/usr/share/doc/file_monitor"
mkdir -p "$PACKAGE_DIR/usr/share/file_monitor"  # Add this line for default config
mkdir -p "$PACKAGE_DIR/usr/bin"

# Copy Debian control files
cp debian/control "$PACKAGE_DIR/DEBIAN/"
cp debian/postinst "$PACKAGE_DIR/DEBIAN/"
cp debian/prerm "$PACKAGE_DIR/DEBIAN/"

# Create an empty conffiles file instead of copying the one with the problematic entry
# We don't need to list /etc/file_monitor/file_monitor.conf since it's created by the postinst script
touch "$PACKAGE_DIR/DEBIAN/conffiles"

# Make scripts executable
chmod 755 "$PACKAGE_DIR/DEBIAN/postinst"
chmod 755 "$PACKAGE_DIR/DEBIAN/prerm"

# Copy application files
cp file_monitor/file_monitor.py "$PACKAGE_DIR/usr/lib/file_monitor/"
# Copy the default config file to usr/share instead of etc
cp debian/file_monitor.conf "$PACKAGE_DIR/usr/share/file_monitor/file_monitor.conf.default"

# Copy and make install_deps.sh executable in the package
cp install_deps.sh "$PACKAGE_DIR/usr/lib/file_monitor/"
chmod 755 "$PACKAGE_DIR/usr/lib/file_monitor/install_deps.sh"

# Create a wrapper script in /usr/bin
echo '#!/bin/bash
python3 /usr/lib/file_monitor/file_monitor.py "$@"' > "$PACKAGE_DIR/usr/bin/file-monitor"
chmod 755 "$PACKAGE_DIR/usr/bin/file-monitor"

# Copy systemd service file
cp debian/file_monitor.service "$PACKAGE_DIR/lib/systemd/system/"

# Build the package
dpkg-deb --build "$PACKAGE_DIR"

# Clean up - remove build directory
echo "Cleaning up build directory..."
rm -rf "$PACKAGE_DIR"

echo "Package built: $PACKAGE_DIR.deb"
echo "To install, run: sudo dpkg -i $PACKAGE_DIR.deb; sudo apt-get install -f"
