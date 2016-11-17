#!/usr/bin/env python

from setuptools import setup


setup(
    name='log_archiver',
    version='0.1.0',
    author='StyleSeat',
    description='Tools for log archival',
    url='https://github.com/styleseat/log_archiver',
    packages=['log_archiver'],
    install_requires=[
        'boto3',
        'PyYAML',
        'requests',
        'watchdog',
    ],
    entry_points={'console_scripts': [
        'archive_logs = log_archiver.archive_logs:main',
    ]},
    platforms='Platform Independent',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Topic :: Internet',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
)
