#!/usr/bin/env python3
"""
File Monitor with Telegram Notifications

This script monitors files and directories specified in a configuration file
and sends Telegram notifications with diffs when changes are detected.
"""
import os
import sys
import time
import logging
import hashlib
import asyncio
import configparser
import socket
import platform
import getpass
from pathlib import Path
from datetime import datetime
import difflib
from typing import Dict, List, Set, Optional, Tuple

from telegram.ext import ApplicationBuilder
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from colorama import Fore, Style, init as colorama_init

# Initialize colorama for colored console output
colorama_init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# Configuration file paths
CONFIG_FILE_PATHS = [
    "/etc/file_monitor/file_monitor.conf",
    os.path.expanduser("~/.config/file_monitor/file_monitor.conf"),
    os.path.join(os.getcwd(), "file_monitor.conf")
]

class FileMonitor:
    """Main class for monitoring files and sending notifications."""
    
    def __init__(self, config_path=None):
        """Initialize the FileMonitor with configuration from config file."""
        # Load configuration
        self.config = configparser.ConfigParser()
        self.config_path = self._find_config_file(config_path)
        
        if not self.config_path:
            logger.error("Configuration file not found in any of the searched locations")
            exit(1)
            
        try:
            self.config.read(self.config_path)
            logger.info(f"Using configuration from: {self.config_path}")
        except Exception as e:
            logger.error(f"Error reading configuration file: {e}")
            exit(1)
        
        # Get required configuration
        self.telegram_token = self.config.get('telegram', 'bot_token', fallback=None)
        self.chat_id = self.config.get('telegram', 'chat_id', fallback=None)
        self.monitor_paths_str = self.config.get('monitor', 'paths', fallback="")
        self.check_interval = self.config.getint('monitor', 'check_interval', fallback=5)
        self.ignore_patterns_str = self.config.get('monitor', 'ignore_patterns', fallback="")
        
        # Validate required configuration
        self._validate_config()
        
        # Parse monitor paths and ignore patterns
        self.monitor_paths = [path.strip() for path in self.monitor_paths_str.split(",") if path.strip()]
        self.ignore_patterns = [pat.strip() for pat in self.ignore_patterns_str.split(",") if pat.strip()]
        
        # Initialize Telegram bot if configured
        self.app = None
        if self.telegram_token and self.chat_id:
            self.app = ApplicationBuilder().token(self.telegram_token).build()
        
        # Store file content hashes for detecting changes
        self.file_hashes: Dict[str, str] = {}
        
        # Store file contents for generating diffs
        self.file_contents: Dict[str, List[str]] = {}
        
        # Initialize observer
        self.observer = Observer()
        
        # Get host information once at startup
        self.host_info = self._get_host_info()
        logger.info(f"Running on host: {self.host_info['hostname']} ({self.host_info['ip']})")
    
    def _find_config_file(self, custom_path=None):
        """Find the configuration file from several possible locations."""
        if custom_path and os.path.isfile(custom_path):
            return custom_path
            
        for path in CONFIG_FILE_PATHS:
            if os.path.isfile(path):
                return path
                
        return None
        
    def _validate_config(self):
        """Validate that required configuration is present."""
        missing_vars = []
        
        if not self.telegram_token:
            missing_vars.append("telegram.bot_token")
        
        if not self.chat_id:
            missing_vars.append("telegram.chat_id")
            
        if not self.monitor_paths_str:
            missing_vars.append("monitor.paths")
        
        if missing_vars:
            logger.error(f"Missing required configuration variables: {', '.join(missing_vars)}")
            logger.error(f"Please check your configuration file: {self.config_path}")
            exit(1)
    
    def _should_ignore(self, path: str) -> bool:
        """Check if a path should be ignored based on ignore patterns."""
        from fnmatch import fnmatch
        
        path = os.path.normpath(path)
        
        for pattern in self.ignore_patterns:
            if fnmatch(path, pattern):
                return True
        
        return False
    
    def _get_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate MD5 hash of a file."""
        try:
            with open(file_path, "rb") as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return None
    
    def _get_file_content(self, file_path: str) -> Optional[List[str]]:
        """Get content of a file as list of lines."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return f.readlines()
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None
    
    def _generate_diff(self, file_path: str, old_content: List[str], new_content: List[str]) -> str:
        """Generate a diff between old and new content."""
        diff = difflib.unified_diff(
            old_content,
            new_content,
            fromfile=f"{file_path} (before)",
            tofile=f"{file_path} (after)",
            lineterm="",
        )
        return "\n".join(diff)
    
    async def _send_telegram_notification(self, message: str):
        """Send a notification to Telegram."""
        if not self.app:
            logger.warning("Telegram bot not configured. Skipping notification.")
            return
        
        try:
            # Split message if it exceeds Telegram maximum length
            max_length = 4096
            for i in range(0, len(message), max_length):
                chunk = message[i:i + max_length]
                await self.app.bot.send_message(chat_id=self.chat_id, text=chunk, parse_mode="HTML")
            
            logger.info(f"Notification sent to Telegram chat {self.chat_id}")
        except Exception as e:
            logger.error(f"Failed to send Telegram notification: {e}")
    
    def _get_host_info(self) -> Dict[str, str]:
        """Get information about the host system."""
        host_info = {}
        
        # Get hostname
        host_info["hostname"] = socket.gethostname()
        
        # Get IP address
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't need to be reachable
            s.connect(('10.255.255.255', 1))
            host_info["ip"] = s.getsockname()[0]
            s.close()
        except Exception:
            try:
                host_info["ip"] = socket.gethostbyname(socket.gethostname())
            except Exception:
                host_info["ip"] = "Unknown"
        
        # Get OS information
        host_info["os"] = platform.platform()
        
        # Get current user
        host_info["user"] = getpass.getuser()
        
        # Get uptime if psutil is available
        try:
            import psutil
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            host_info["uptime"] = str(uptime).split('.')[0]  # Remove microseconds
        except ImportError:
            host_info["uptime"] = "Unknown"
        
        return host_info
    
    async def _handle_file_change(self, file_path: str, event_type: str):
        """Handle file change event."""
        if self._should_ignore(file_path):
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Skip processing for deletion events
        if event_type == "deleted":
            notification = f"📁 <b>File Monitor Alert</b>\n\n"
            notification += f"⏰ <b>Time:</b> {timestamp}\n"
            notification += f"🖥️ <b>Host:</b> {self.host_info['hostname']} ({self.host_info['ip']})\n"
            notification += f"👤 <b>User:</b> {self.host_info['user']}\n"
            notification += f"💻 <b>OS:</b> {self.host_info['os']}\n"
            notification += f"🔄 <b>Event:</b> {event_type.upper()}\n"
            notification += f"📄 <b>File:</b> {file_path}\n"
            
            logger.info(f"{Fore.RED}File {file_path} was deleted{Style.RESET_ALL}")
            await self._send_telegram_notification(notification)
            
            # Remove file from tracking
            self.file_hashes.pop(file_path, None)
            self.file_contents.pop(file_path, None)
            return
        
        # Check if file exists and is readable
        if not os.path.isfile(file_path):
            return
        
        # Get new hash and content
        new_hash = self._get_file_hash(file_path)
        if not new_hash:
            return
        
        # Get file content for diffing
        new_content = self._get_file_content(file_path)
        if not new_content:
            return
        
        # Check if this is a new file or changed file
        old_hash = self.file_hashes.get(file_path)
        if old_hash is None:
            # New file
            logger.info(f"{Fore.GREEN}New file detected: {file_path}{Style.RESET_ALL}")
            
            notification = f"📁 <b>File Monitor Alert</b>\n\n"
            notification += f"⏰ <b>Time:</b> {timestamp}\n"
            notification += f"🖥️ <b>Host:</b> {self.host_info['hostname']} ({self.host_info['ip']})\n"
            notification += f"👤 <b>User:</b> {self.host_info['user']}\n"
            notification += f"💻 <b>OS:</b> {self.host_info['os']}\n"
            notification += f"🔄 <b>Event:</b> NEW FILE\n"
            notification += f"📄 <b>File:</b> {file_path}\n\n"
            notification += f"<pre>New file created with {len(new_content)} lines</pre>"
            
            await self._send_telegram_notification(notification)
            
        elif old_hash != new_hash:
            # Changed file
            logger.info(f"{Fore.YELLOW}File changed: {file_path}{Style.RESET_ALL}")
            
            old_content = self.file_contents.get(file_path, [])
            diff = self._generate_diff(file_path, old_content, new_content)
            
            notification = f"📁 <b>File Monitor Alert</b>\n\n"
            notification += f"⏰ <b>Time:</b> {timestamp}\n"
            notification += f"🖥️ <b>Host:</b> {self.host_info['hostname']} ({self.host_info['ip']})\n"
            notification += f"👤 <b>User:</b> {self.host_info['user']}\n"
            notification += f"💻 <b>OS:</b> {self.host_info['os']}\n"
            notification += f"🔄 <b>Event:</b> MODIFIED\n"
            notification += f"📄 <b>File:</b> {file_path}\n\n"
            notification += f"<pre>{diff}</pre>"
            
            await self._send_telegram_notification(notification)
        
        # Update hash and content
        self.file_hashes[file_path] = new_hash
        self.file_contents[file_path] = new_content
    
    def _scan_directory(self, directory: str) -> Set[str]:
        """Scan a directory recursively and return all files."""
        files = set()
        try:
            for root, _, filenames in os.walk(directory):
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    if not self._should_ignore(file_path) and os.path.isfile(file_path):
                        files.add(file_path)
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
        
        return files
    
    def _scan_all_paths(self) -> Set[str]:
        """Scan all monitored paths and return all files."""
        all_files = set()
        
        for path in self.monitor_paths:
            path = os.path.abspath(path)
            
            if not os.path.exists(path):
                logger.warning(f"Path does not exist: {path}")
                continue
            
            if os.path.isfile(path) and not self._should_ignore(path):
                all_files.add(path)
            elif os.path.isdir(path):
                all_files.update(self._scan_directory(path))
        
        return all_files
    
    def start_monitoring(self):
        """Start monitoring files and directories."""
        logger.info(f"{Fore.CYAN}Starting file monitor...{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}Monitoring paths: {', '.join(self.monitor_paths)}{Style.RESET_ALL}")
        
        # Create event handler
        event_handler = FileChangeHandler(self)
        
        # Setup watchdog observer for each path
        for path in self.monitor_paths:
            path = os.path.abspath(path)
            
            if not os.path.exists(path):
                logger.warning(f"Path does not exist: {path}")
                continue
            
            if os.path.isdir(path):
                self.observer.schedule(event_handler, path, recursive=True)
                logger.info(f"Monitoring directory: {path}")
            elif os.path.isfile(path):
                parent_dir = os.path.dirname(path)
                self.observer.schedule(event_handler, parent_dir, recursive=False)
                logger.info(f"Monitoring file: {path}")
        
        # Initial scan of all files
        all_files = self._scan_all_paths()
        logger.info(f"Found {len(all_files)} files to monitor")
        
        # Store initial state
        for file_path in all_files:
            file_hash = self._get_file_hash(file_path)
            file_content = self._get_file_content(file_path)
            
            if file_hash and file_content:
                self.file_hashes[file_path] = file_hash
                self.file_contents[file_path] = file_content
        
        # Start observer
        self.observer.start()
        logger.info(f"{Fore.GREEN}File monitor started successfully!{Style.RESET_ALL}")
        
        try:
            # Keep the main thread running
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping file monitor...")
            self.observer.stop()
        
        self.observer.join()
        logger.info("File monitor stopped")


class FileChangeHandler(FileSystemEventHandler):
    """Watchdog event handler for file system events."""
    
    def __init__(self, file_monitor: FileMonitor):
        """Initialize with a reference to the FileMonitor."""
        self.file_monitor = file_monitor
        # Create event loop for async operations
        self.loop = asyncio.new_event_loop()
    
    def on_created(self, event: FileSystemEvent):
        """Handle file creation event."""
        if not event.is_directory:
            self.loop.run_until_complete(self.file_monitor._handle_file_change(event.src_path, "created"))
    
    def on_modified(self, event: FileSystemEvent):
        """Handle file modification event."""
        if not event.is_directory:
            self.loop.run_until_complete(self.file_monitor._handle_file_change(event.src_path, "modified"))
    
    def on_deleted(self, event: FileSystemEvent):
        """Handle file deletion event."""
        if not event.is_directory:
            self.loop.run_until_complete(self.file_monitor._handle_file_change(event.src_path, "deleted"))
    
    def on_moved(self, event: FileSystemEvent):
        """Handle file move event."""
        if not event.is_directory:
            # Treat as delete + create
            self.loop.run_until_complete(self.file_monitor._handle_file_change(event.src_path, "deleted"))
            self.loop.run_until_complete(self.file_monitor._handle_file_change(event.dest_path, "created"))


def main(config_path=None):
    """Main entry point."""
    try:
        monitor = FileMonitor(config_path)
        monitor.start_monitoring()
        return 0
    except Exception as e:
        logger.error(f"Error in main: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())