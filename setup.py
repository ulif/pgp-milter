import os
from setuptools import setup, find_packages


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


install_requires = [
    "pymilter",
    "PGPy",
]

tests_require = [
    "coverage[toml]>=5.0.2",
    "pytest>=4.3.0",
]


setup(
    name="pgp-milter",
    version="0.1.dev0",  # also change __init__.py
    description="Mail filter for automatic PGP-encryption of messages.",
    long_description=read("README.rst")
    + "\n\n\n"
    + read("CHANGES.rst")
    + "\n\n\n",
    long_description_content_type="text/x-rst",
    url="https://github.com/ulif/pgp-milter",
    author="ulif",
    author_email="uli@gnufix.de",
    license="GPL-3.0-or-later AND CC-BY-SA-4.0",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Topic :: Security :: Cryptography",
        (
            "License :: OSI Approved :: "
            "GNU General Public License v3 or later (GPLv3+)"
        ),
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: CPython",
    ],
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=install_requires,
    extras_require={"tests": tests_require, },
    tests_require=tests_require,
    zip_safe=False,
    entry_points={"console_scripts": ["pgp-milter = pgp_milter:main"]},
)
