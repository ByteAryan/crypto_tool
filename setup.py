"""Setup file for crypto_tool package."""
from setuptools import setup, find_packages

setup(
    name="crypto_tool",
    version="2.0.0",
    description="Comprehensive cryptography tool with multiple encryption algorithms",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
        "flask>=2.0.0",
        "numpy>=1.20.0",
    ],
    python_requires=">=3.7",
)
