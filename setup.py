from setuptools import setup, find_packages

setup(
    name="menuscript",
    version="0.8.0-dev",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[],
    entry_points={
        "console_scripts": [
            "menuscript=menuscript.main:main"
        ]
    },
)
