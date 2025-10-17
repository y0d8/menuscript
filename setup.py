from setuptools import setup, find_packages
setup(
    name='menuscript',
    version='0.4.0',
    packages=find_packages(),
    install_requires=[],
    entry_points={'console_scripts':['menuscript = menuscript.main:main']}
)
