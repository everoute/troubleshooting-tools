#!/usr/bin/env python3
"""
Traffic Analyzer - 网络流量分析工具安装脚本
"""

from setuptools import setup, find_packages
from pathlib import Path

# 读取README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name="traffic-analyzer",
    version="1.0.0",
    author="Network Analysis Team",
    description="基于内核调研的高性能网络流量分析工具",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/traffic-analyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pandas>=1.5.0",
        "numpy>=1.24.0",
        "scipy>=1.9.0",
        "PyYAML>=6.0",
        "tqdm>=4.65.0",
        "colorama>=0.4.6",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=22.0",
            "flake8>=5.0",
        ],
        "visual": [
            "matplotlib>=3.6.0",
            "seaborn>=0.12.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "tcp-analyzer=bin.tcp_analyzer_cli:main",
            "pcap-analyzer=bin.pcap_analyzer_cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
