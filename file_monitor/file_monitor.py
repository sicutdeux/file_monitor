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
LOG_FILE = "/var/log/file_modifier.logs"

# Create directory for log file if it doesn't exist
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Setup both file and console handlers
logger = logging.getLogger("file_monitor")
logger.setLevel(logging.DEBUG)

# Console handler with INFO level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
console_handler.setFormatter(console_formatter)

# File handler with DEBUG level for more detailed logging
try:
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    logger.info(f"Logging to file: {LOG_FILE}")
except PermissionError:
    print(f"Warning: Cannot write to log file {LOG_FILE} (permission denied). Continuing with console logging only.")
except Exception as e:
    print(f"Warning: Cannot write to log file {LOG_FILE}: {str(e)}. Continuing with console logging only.")

logger.addHandler(console_handler)

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
        self.throttle_max_changes = self.config.getint('monitor', 'throttle_max_changes', fallback=5)
        self.throttle_window = self.config.getint('monitor', 'throttle_window', fallback=3)
        self.debug_mode = self.config.getboolean('monitor', 'debug_mode', fallback=False)
        
        # If debug mode is enabled, set logger to DEBUG level
        if self.debug_mode:
            console_handler.setLevel(logging.DEBUG)
            logger.debug("Debug mode enabled")
        
        # Initialize throttling buffers
        self.change_buffer: List[Tuple[str, str, datetime, Optional[str]]] = []  # [(file_path, event_type, timestamp, diff)]
        self.last_notification_time = datetime.now()
        
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
            logger.debug(f"Attempting to read content of file: {file_path}")
            
            # Check if file exists and is readable
            if not os.path.exists(file_path):
                logger.warning(f"File does not exist: {file_path}")
                return None
                
            if not os.access(file_path, os.R_OK):
                logger.warning(f"File is not readable (permission denied): {file_path}")
                return None
                
            # Check file size to avoid reading very large files
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                logger.warning(f"File is too large to read (size: {file_size/1024/1024:.2f}MB): {file_path}")
                return None
                
            # Check if file is binary
            with open(file_path, "rb") as f:
                chunk = f.read(1024)
                if b'\0' in chunk:  # Simple check for null bytes
                    logger.debug(f"File appears to be binary: {file_path}")
            
            # Try to read as text
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.readlines()
                logger.debug(f"Successfully read {len(content)} lines from {file_path}")
                return content
        except UnicodeDecodeError as e:
            logger.warning(f"Unicode decode error reading {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None
    
    def _generate_diff(self, file_path: str, old_content: List[str], new_content: List[str]) -> str:
        """Generate a diff between old and new content."""
        logger.debug(f"Generating diff for {file_path}")
        
        # Log detailed debug information
        logger.debug(f"Old content: {len(old_content)} lines, New content: {len(new_content)} lines")
        
        if not old_content and not new_content:
            logger.debug(f"Both old and new content are empty for {file_path}")
            return ""
            
        if not old_content:
            logger.debug(f"No old content available for {file_path}, cannot generate diff")
            return ""
            
        if not new_content:
            logger.debug(f"No new content available for {file_path}, cannot generate diff")
            return ""
        
        try:
            diff = difflib.unified_diff(
                old_content,
                new_content,
                fromfile=f"{file_path} (before)",
                tofile=f"{file_path} (after)",
                lineterm="",
            )
            
            diff_result = "\n".join(diff)
            
            if not diff_result:
                logger.debug(f"No textual differences found between old and new content for {file_path}")
            else:
                logger.debug(f"Diff generated for {file_path}: {len(diff_result)} characters")
                
            return diff_result
        except Exception as e:
            logger.error(f"Error generating diff for {file_path}: {e}")
            return ""
    
    def _format_batch_notification(self, changes: List[Tuple[str, str, datetime, Optional[str]]]) -> str:
        """Format a batch of changes into a single notification message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Group changes by type
        changes_by_type = {}
        for file_path, event_type, event_time, diff in changes:
            if event_type not in changes_by_type:
                changes_by_type[event_type] = []
            changes_by_type[event_type].append((file_path, event_time, diff))
        
        notification = f"📁 <b>File Monitor Alert (Batch Update)</b>\n\n"
        notification += f"⏰ <b>Time:</b> {timestamp}\n"
        notification += f"🖥️ <b>Host:</b> {self.host_info['hostname']} ({self.host_info['ip']})\n"
        notification += f"👤 <b>User:</b> {self.host_info['user']}\n"
        notification += f"💻 <b>OS:</b> {self.host_info['os']}\n\n"
        
        # Add a summary of changes
        notification += f"<b>Summary of Changes:</b>\n"
        for event_type, files in changes_by_type.items():
            notification += f"  • {event_type.upper()}: {len(files)} files\n"
        notification += "\n"
        
        # Process each change type with detailed information
        for event_type, files in changes_by_type.items():
            icon = "➕" if event_type == "created" else "✏️" if event_type == "modified" else "❌"
            notification += f"{icon} <b>{event_type.upper()} ({len(files)} files)</b>\n"
            
            for file_path, event_time, diff in files:
                # Format timestamp for this specific event
                event_time_str = event_time.strftime("%H:%M:%S")
                file_size = "N/A"
                
                # Get file details if it exists
                if event_type != "deleted" and os.path.exists(file_path):
                    try:
                        file_size = f"{os.path.getsize(file_path)/1024:.1f} KB"
                    except Exception:
                        pass
                
                # File path with size information
                if event_type == "deleted":
                    notification += f"  • <b>{file_path}</b> at {event_time_str}\n"
                else:
                    notification += f"  • <b>{file_path}</b> ({file_size}) at {event_time_str}\n"
                
                # Handle diff information
                if diff and diff.strip():  # Check if diff is not empty
                    # Count lines changed
                    added_lines = diff.count('\n+') - 1  # Subtract the +++ line
                    removed_lines = diff.count('\n-') - 1  # Subtract the --- line
                    
                    notification += f"    <i>Changed: +{added_lines} -{removed_lines} lines</i>\n"
                    
                    # Limit diff size to avoid Telegram message limits
                    if len(diff) > 1000:
                        shortened_diff = diff[:997] + "..."
                        notification += f"<pre>{shortened_diff}</pre>\n"
                        notification += f"<i>(Diff truncated, full details in log)</i>\n"
                    else:
                        # Escape HTML characters that might cause rendering issues
                        safe_diff = diff.replace("<", "&lt;").replace(">", "&gt;")
                        notification += f"<pre>{safe_diff}</pre>\n"
                elif event_type == "modified" and diff is not None and not diff.strip():
                    notification += f"    <i>(Binary file or no textual changes detected)</i>\n"
            
            notification += "\n"
        
        return notification

    async def _process_change_buffer(self):
        """Process and send notifications for buffered changes."""
        current_time = datetime.now()
        
        # Check if we should process the buffer
        if (len(self.change_buffer) >= self.throttle_max_changes or 
            (self.change_buffer and (current_time - self.last_notification_time).total_seconds() >= self.throttle_window)):
            
            # Create notification for all changes
            notification = self._format_batch_notification(self.change_buffer)
            await self._send_telegram_notification(notification)
            
            # Clear buffer and update time
            self.change_buffer = []
            self.last_notification_time = current_time

    async def _send_telegram_notification(self, message: str):
        """Send a notification to Telegram."""
        if not self.app:
            logger.warning("Telegram bot not configured. Skipping notification.")
            return
        
        try:
            # Get telegram message max length
            max_length = 4096
            
            # If message is short enough, send it directly
            if len(message) <= max_length:
                await self.app.bot.send_message(chat_id=self.chat_id, text=message, parse_mode="HTML")
                logger.info(f"Notification sent to Telegram chat {self.chat_id}")
                return
            
            # Split message into parts at line breaks
            lines = message.split('\n')
            parts = []
            current_part = ""
            
            for line in lines:
                # If adding this line would exceed the limit, start a new part
                if len(current_part + line + '\n') > max_length - 30:  # Leave room for part indicator
                    parts.append(current_part)
                    current_part = line + '\n'
                else:
                    current_part += line + '\n'
            
            # Add the last part if not empty
            if current_part:
                parts.append(current_part)
            
            # Send each part with pagination indicator
            total_parts = len(parts)
            for i, part in enumerate(parts, 1):
                # Add pagination indicator
                if total_parts > 1:
                    part_indicator = f"\n\n<b>--- Part {i}/{total_parts} ---</b>"
                    if i == 1:
                        # For first part, add at the end
                        part_with_indicator = part + part_indicator
                    else:
                        # For subsequent parts, add at the beginning
                        part_with_indicator = f"<b>--- Part {i}/{total_parts} ---</b>\n\n" + part
                    
                    await self.app.bot.send_message(
                        chat_id=self.chat_id, 
                        text=part_with_indicator, 
                        parse_mode="HTML"
                    )
                else:
                    # Only one part, send as is
                    await self.app.bot.send_message(
                        chat_id=self.chat_id, 
                        text=part, 
                        parse_mode="HTML"
                    )
                
                # Small delay between messages to maintain order and avoid rate limits
                # Increased from 0.5 to 1.0 seconds to better respect Telegram's rate limits
                await asyncio.sleep(1.0)
            
            logger.info(f"Notification sent to Telegram chat {self.chat_id} in {total_parts} parts")
        except Exception as e:
            logger.error(f"Failed to send Telegram notification: {e}")
            # Log the message that failed to send for debugging
            if len(message) > 200:
                logger.debug(f"Failed message (truncated): {message[:200]}...")
            else:
                logger.debug(f"Failed message: {message}")

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
        logger.debug(f"Handling {event_type} event for {file_path}")
        
        if self._should_ignore(file_path):
            logger.debug(f"Ignoring {file_path} based on ignore patterns")
            return
        
        current_time = datetime.now()
        
        # Handle deletion events
        if event_type == "deleted":
            logger.debug(f"Processing deletion of {file_path}")
            
            # Get details about the file before removing from tracking
            was_tracked = file_path in self.file_hashes
            
            # Remove from tracking
            self.file_hashes.pop(file_path, None)
            self.file_contents.pop(file_path, None)
            
            if was_tracked:
                logger.info(f"Tracked file was deleted: {file_path}")
            else:
                logger.info(f"Untracked file was deleted: {file_path}")
                
            # Add to change buffer
            self.change_buffer.append((file_path, event_type, current_time, None))
            
        elif event_type == "created":
            if os.path.isfile(file_path):
                logger.debug(f"Processing newly created file {file_path}")
                
                # Check if we already know about this file
                if file_path in self.file_hashes:
                    logger.debug(f"File {file_path} already tracked - treating as modification")
                    event_type = "modified"
                
                # Calculate hash and read content
                new_hash = self._get_file_hash(file_path)
                if new_hash is None:
                    logger.warning(f"Could not calculate hash for newly created file {file_path}")
                    return
                
                new_content = self._get_file_content(file_path)
                if new_content is None:
                    logger.warning(f"Could not read content for newly created file {file_path}")
                    # Track the file even if we can't read the content
                    self.change_buffer.append((file_path, event_type, current_time, None))
                    self.file_hashes[file_path] = new_hash
                    return
                
                # For new files, we don't need to generate a diff
                self.change_buffer.append((file_path, event_type, current_time, None))
                
                # Track the new file
                self.file_hashes[file_path] = new_hash
                self.file_contents[file_path] = new_content
                
                
        elif event_type == "modified":
            if os.path.isfile(file_path):
                logger.debug(f"Processing modification of file {file_path}")
                
                # Calculate new hash
                new_hash = self._get_file_hash(file_path)
                if new_hash is None:
                    logger.warning(f"Could not calculate hash for {file_path}")
                    return
                
                # Check if the file was previously unknown
                if file_path not in self.file_hashes:
                    logger.debug(f"File {file_path} was not previously tracked - treating as new file")
                    await self._handle_file_change(file_path, "created")
                    return
                
                # Check if hash actually changed
                old_hash = self.file_hashes.get(file_path)
                if old_hash == new_hash:
                    logger.debug(f"File {file_path} reported as modified but hash hasn't changed (hash: {new_hash}). Ignoring.")
                    return
                
                # Read new content
                new_content = self._get_file_content(file_path)
                if new_content is None:
                    # Fixed comma in f-string - was causing a syntax error
                    logger.warning(f"Could not read content for modified file {file_path}, will track change without diff")
                    self.change_buffer.append((file_path, event_type, current_time, None))
                    self.file_hashes[file_path] = new_hash
                    return
                
                old_content = self.file_contents.get(file_path, [])
                
                # Generate diff for modified files
                diff = None
                if old_content:
                    if isinstance(old_content, list) and isinstance(new_content, list):
                        logger.debug(f"Generating diff for modified file {file_path}")
                        diff = self._generate_diff(file_path, old_content, new_content)
                        
                        if diff:
                            # Count lines changed for logging
                            added_lines = diff.count('\n+') - 1  # Subtract the +++ line
                            removed_lines = diff.count('\n-') - 1  # Subtract the --- line
                            logger.info(f"File modified: {file_path} (+{added_lines}/-{removed_lines} lines)")
                            logger.debug(f"Generated diff for {file_path}: {len(diff)} characters")
                        else:
                            logger.debug(f"No diff generated for {file_path} - content identical or formatting only changes")
                            logger.info(f"File modified: {file_path} (no textual changes detected)")
                    else:
                        logger.warning(f"Cannot generate diff for {file_path} - content types unexpected: old={type(old_content)}, new={type(new_content)}")
                else:
                    # Fixed comma in f-string - was causing a syntax error
                    logger.debug(f"No previous content available for {file_path}, cannot generate diff")
                
                # Add to buffer with diff if available
                self.change_buffer.append((file_path, event_type, current_time, diff if diff else None))
                
                # Update tracked state
                self.file_hashes[file_path] = new_hash
                self.file_contents[file_path] = new_content
        
        # Use colors for console output based on event type
        color = Fore.GREEN if event_type == "created" else Fore.YELLOW if event_type == "modified" else Fore.RED
        logger.info(f"{color}Change detected: {event_type} - {file_path}{Style.RESET_ALL}")
        
        # Process change buffer if needed
        await self._process_change_buffer()
    
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
        logger.info(f"{Fore.CYAN}Starting file monitor v{VERSION}...{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}Monitoring paths: {', '.join(self.monitor_paths)}{Style.RESET_ALL}")
        
        if self.ignore_patterns:
            logger.info(f"Ignoring patterns: {', '.join(self.ignore_patterns)}")
        
        # Create event handler
        event_handler = FileChangeHandler(self)
        
        # Setup watchdog observer for each path
        monitored_dirs = set()
        for path in self.monitor_paths:
            path = os.path.abspath(path)
            
            if not os.path.exists(path):
                logger.warning(f"Path does not exist: {path}")
                continue
            
            if os.path.isdir(path):
                if path not in monitored_dirs:  # Avoid monitoring the same directory twice
                    self.observer.schedule(event_handler, path, recursive=True)
                    monitored_dirs.add(path)
                    logger.info(f"Monitoring directory: {path} (recursive)")
            elif os.path.isfile(path):
                parent_dir = os.path.dirname(path)
                if parent_dir not in monitored_dirs:  # Avoid monitoring the same directory twice
                    self.observer.schedule(event_handler, parent_dir, recursive=False)
                    monitored_dirs.add(parent_dir)
                    logger.info(f"Monitoring file: {path}")
        
        # Initial scan of all files
        all_files = self._scan_all_paths()
        logger.info(f"Found {len(all_files)} files to monitor")
        
        # Store initial state
        files_indexed = 0
        for file_path in all_files:
            try:
                file_hash = self._get_file_hash(file_path)
                file_content = self._get_file_content(file_path)
                
                if file_hash and file_content:
                    self.file_hashes[file_path] = file_hash
                    self.file_contents[file_path] = file_content
                    files_indexed += 1
            except Exception as e:
                logger.error(f"Error indexing file {file_path}: {e}")
        
        logger.info(f"Successfully indexed {files_indexed} of {len(all_files)} files")
        
        # Start observer
        self.observer.start()
        logger.info(f"{Fore.GREEN}File monitor started successfully!{Style.RESET_ALL}")
        
        # Send startup notification if configured
        startup_message = (
            f"📁 <b>File Monitor v{VERSION} Started</b>\n\n"
            f"🖥️ <b>Host:</b> {self.host_info['hostname']} ({self.host_info['ip']})\n"
            f"👤 <b>User:</b> {self.host_info['user']}\n"
            f"💻 <b>OS:</b> {self.host_info['os']}\n"
            f"⏰ <b>Started at:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"🔍 <b>Monitoring:</b> {len(all_files)} files in {len(self.monitor_paths)} paths\n"
        )
        
        try:
            # Use asyncio.run instead of get_event_loop for better compatibility
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._send_telegram_notification(startup_message))
        except ConnectionError as e:
            logger.error(f"Network error sending startup notification: {e}")
        except Exception as e:
            logger.error(f"Failed to send startup notification: {e}")
        
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


VERSION = "1.4.1"

def main(config_path=None):
    """Main entry point."""
    # Print version if --version flag is passed
    if len(sys.argv) > 1 and sys.argv[1] == '--version':
        print(f"File Monitor v{VERSION}")
        return 0
    try:
        monitor = FileMonitor(config_path)
        monitor.start_monitoring()
        return 0
    except Exception as e:
        logger.error(f"Error in main: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
