"""
******************************************************************************
 * FILE:        /setup.py
 * LAYER:       Project Layer
 * MODULE:      Setup
 * PURPOSE:     Package installation configuration
 * DOMAIN:      DCAVP Core
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-11
 * UPDATED:     2026-05-11
 * VERSION:     v0.1.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

import pathlib
from setuptools import setup, find_packages

setup(
    name='dcavp',
    version='0.1.0',
    description='Deterministic security analysis for AI-generated Python code',
    long_description=pathlib.Path('README.md').read_text(encoding='utf-8'),
    long_description_content_type='text/markdown',
    author='DCAVP Engineering',
    url='https://github.com/dcavp/dcavp',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    python_requires='>=3.12',
    install_requires=[],
    entry_points={
        'console_scripts': [
            'dcavp=interfaces.cli.dcavp_cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Quality Assurance',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.12',
    ],
)
