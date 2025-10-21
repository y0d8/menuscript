#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name='menuscript',
    version='0.4.0',
    packages=find_packages(),
    install_requires=[
        'click>=8.0.0',
    ],
    entry_points={
        'console_scripts': [
            'menuscript=menuscript.main:main',
        ],
    },
    python_requires='>=3.8',
)
