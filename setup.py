#!/usr/bin/env python3

from setuptools import setup, find_packages
from file_monitor import __version__

setup(
    name="file-monitor",
    version=__version__,
    description="File monitor with Telegram notifications",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourusername/file-monitor",
    packages=find_packages(),
    scripts=["bin/file-monitor"],
    install_requires=[
        "python-telegram-bot",
        "watchdog",
        "colorama",
        "python-dotenv",
    ],
    data_files=[
        ('/etc/file_monitor', ['debian/file_monitor.conf']),
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
)
