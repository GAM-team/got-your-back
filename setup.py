# -*- coding: utf-8 -*-
from setuptools import setup

# from gyb import __author__, __email__, __program_name__, __version__

__author__ = "Jay Lee"
__email__ = 'jay0lee@gmail.com'
__program_name__ = 'Got Your Back: Gmail Backup'
__version__ = '1.80'


with open("README.md", "r") as _:
    readme = _.read()

setup(
    name="gyb",
    version=__version__,
    packages=["."],
    zip_safe=True,
    url="https://github.com/GAM-team/got-your-back",
    license="Apache 2.0",
    author=__author__,
    author_email=__email__,
    description=__program_name__,
    long_description=readme,
    long_description_content_type="text/markdown",
    python_requires=">=3.7",
    install_requires=[
        "httplib2>=0.17.0",
        "google-api-python-client>=2.0",
        "google-auth>=1.11.2",
        "google-auth-httplib2",
        "google-auth-oauthlib>=0.4.1",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Communications :: Email",
        "Topic :: Utilities",
    ],
    entry_points={
        "console_scripts": [
            "gyb=gyb:_installed_main"
        ],
    }
)
