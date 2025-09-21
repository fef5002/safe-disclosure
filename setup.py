#!/usr/bin/env python3
"""Setup script for safe-disclosure package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="safe-disclosure",
    version="0.1.0",
    author="FFoster",
    description="Kit to safely redact real entities from documents using tokens and roles",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fef5002/safe-disclosure",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=3.4.0",
        "pyyaml>=5.4.0",
        "click>=8.0.0",
    ],
    entry_points={
        "console_scripts": [
            "safe-disclosure=safe_disclosure.cli:main",
        ],
    },
)