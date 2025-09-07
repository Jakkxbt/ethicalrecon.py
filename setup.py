#!/usr/bin/env python3
"""
EthicalRecon Setup Script
Installation and distribution setup for the vulnerability scanner
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    try:
        with open('README.md', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "EthicalRecon - Comprehensive Ethical Hacking Reconnaissance Toolkit"

# Read requirements
def read_requirements():
    try:
        with open('requirements.txt', 'r') as f:
            requirements = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Handle version specifiers
                    if '>=' in line:
                        requirements.append(line)
                    else:
                        requirements.append(line)
            return requirements
    except FileNotFoundError:
        return [
            'requests>=2.28.0',
            'colorama>=0.4.6',
            'urllib3>=1.26.0',
            'PyYAML>=6.0'
        ]

setup(
    name='ethicalrecon',
    version='2.0.0',
    author='Security Research Team',
    author_email='security@example.com',
    description='Comprehensive Ethical Hacking Reconnaissance Toolkit',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/ethicalrecon',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Testing',
    ],
    python_requires='>=3.8',
    install_requires=read_requirements(),
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'black>=22.0.0',
            'flake8>=5.0.0',
            'mypy>=1.0.0',
        ],
        'advanced': [
            'httpx>=0.24.0',
            'aiohttp>=3.8.0',
            'beautifulsoup4>=4.11.0',
            'scikit-learn>=1.2.0',
            'numpy>=1.24.0',
        ],
        'full': [
            'httpx>=0.24.0',
            'aiohttp>=3.8.0',
            'beautifulsoup4>=4.11.0',
            'lxml>=4.9.0',
            'scikit-learn>=1.2.0',
            'numpy>=1.24.0',
            'jinja2>=3.1.0',
            'dnspython>=2.3.0',
            'psutil>=5.9.0',
        ]
    },
    entry_points={
        'console_scripts': [
            'ethicalrecon=ethicalrecon:main',
        ],
    },
    include_package_data=True,
    package_data={
        'ethicalrecon': [
            'payloads/*.txt',
            'config.yaml',
            'templates/*.html',
            'templates/*.json',
            'wordlists/*.txt',
        ],
    },
    zip_safe=False,
    keywords='security vulnerability scanner penetration-testing bug-bounty ethical-hacking reconnaissance',
    project_urls={
        'Bug Reports': 'https://github.com/yourusername/ethicalrecon/issues',
        'Source': 'https://github.com/yourusername/ethicalrecon',
        'Documentation': 'https://github.com/yourusername/ethicalrecon/wiki',
    },
)
