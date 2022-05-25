from setuptools import setup

setup(
    name="pycredential",
    version="1.0",
    description="Store credentials encrypted for script usage",
    author="Jonas Zinn",
    author_email="jonas.zinn@uni-konstanz.de",
    packages=["pycredential"],
    install_requires=["pycryptodomex"]
)
