# File Monitor

A utility that monitors files and directories for changes and sends notifications through Telegram when changes are detected.

## Features

- Monitor multiple files and directories for changes
- Send real-time notifications via Telegram
- Include file diffs in notifications
- Ignore files based on patterns
- Easy configuration
- Available as a Debian/Ubuntu package or installable via pip

## Installation

### Method 1: Using the Debian/Ubuntu package (Recommended)

1. Install required build dependencies:
   ```bash
   sudo apt update
   sudo apt install -y build-essential debhelper dh-python python3-pip
   ```

2. Build the Debian package:
   ```bash
   git clone https://github.com/sicutdeux/file_monitor.git
   cd file-monitor
   chmod +x build_deb.sh
   sudo ./build_deb.sh
   ```

3. Install the package:
   ```bash
   sudo dpkg -i file-monitor-*.deb
   sudo apt-get install -f  # To resolve any dependency issues
   ```

### Method 2: Using pip

1. Install pip and dependencies:
   ```bash
   sudo apt update
   sudo apt install -y python3-pip
   ```

2. Install the package:
   ```bash
   pip3 install git+https://github.com/sicutdeux/file_monitor.git
   ```

### Installing dependencies manually

If you prefer to install dependencies manually:
```bash
sudo apt update
sudo apt install -y python3-pip
sudo pip3 install python-telegram-bot watchdog colorama python-dotenv
```

## Configuration

### Package Installation (Method 1)

Edit the configuration file at `/etc/file_monitor/file_monitor.conf`:

```bash
sudo nano /etc/file_monitor/file_monitor.conf
```

### Pip Installation (Method 2)

1. Create a configuration file in one of these locations:
   - `/etc/file_monitor/file_monitor.conf`
   - `~/.config/file_monitor/file_monitor.conf`
   - `./file_monitor.conf` (in the current working directory)

2. Use the following template:

```ini
[telegram]
# Your Telegram bot token from BotFather
bot_token = YOUR_BOT_TOKEN

# Telegram chat ID where notifications will be sent
chat_id = YOUR_CHAT_ID

[monitor]
# Comma-separated list of paths to monitor (files or directories)
paths = /path/to/file1.txt, /path/to/directory1

# Interval in seconds to check for changes
check_interval = 5

# Comma-separated list of glob patterns to ignore
# Example: *.tmp, *~, .git/*
ignore_patterns = .git/*, *.tmp, *~, __pycache__/*, *.pyc
```

## Getting a Telegram Bot Token and Chat ID

1. Create a Telegram bot by talking to [@BotFather](https://t.me/BotFather)
2. Send a message to your bot
3. Get your chat ID by visiting `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`

## Usage

If installed via Debian package or pip:

```bash
file-monitor
```

With a custom configuration file:

```bash
file-monitor --config /path/to/your/config.conf
```

## Building from Source

```bash
git clone https://github.com/sicutdeux/file_monitor.git
cd file-monitor

# Install dependencies
pip install -r requirements.txt

# Run directly
python -m file_monitor.file_monitor
```

## Building the Debian Package Manually

```bash
git clone https://github.com/sicutdeux/file_monitor.git
cd file-monitor

# Make sure the scripts are executable
chmod +x bin/file-monitor
chmod +x debian/rules
chmod +x debian/postinst
chmod +x debian/postrm

# Install build dependencies
sudo apt-get update
sudo apt-get install -y debhelper dh-python python3-all python3-setuptools

# Build the package
dpkg-buildpackage -us -uc -b

# Install the package
sudo dpkg -i ../file-monitor_*.deb
sudo apt-get install -f  # Fix dependencies if needed
```

## Troubleshooting

### Package Installation Issues
If you encounter dependency issues, run:
```bash
sudo apt-get update
sudo apt-get install -f
```

### Permission Issues
Ensure the configuration file has the correct permissions:
```bash
sudo chmod 640 /etc/file_monitor/file_monitor.conf
sudo chown root:root /etc/file_monitor/file_monitor.conf
```

## License

MIT License
