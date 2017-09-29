import os
from os.path import abspath, dirname, join
from setuptools import setup

"""
New release procedure

- edit pierky/mactopeer/version.py

- edit CHANGES.rst

- verify RST syntax is ok
    python setup.py --long-description | rst2html.py --strict

- update the USAGE file:

 cat << EOF > USAGE.rst
Usage
-----

.. code::

EOF
 ./scripts/mactopeer --help | sed 's/^/  /' >> USAGE.rst
 cat << EOF >> USAGE.rst


Devices JSON file schema
------------------------

.. code::

EOF
 ./scripts/mactopeer --help-devices | sed 's/^/  /' >> USAGE.rst

- python setup.py sdist

- ~/.local/bin/twine upload dist/*

- git push

- edit new release on GitHub
"""

__version__ = None

# Allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

# Get proper long description for package
current_dir = dirname(abspath(__file__))
description = open(join(current_dir, "README.rst")).read()
changes = open(join(current_dir, "CHANGES.rst")).read()
long_description = '\n\n'.join([description, changes])
exec(open(join(current_dir, "pierky/mactopeer/version.py")).read())

install_requires = []
with open("requirements.txt", "r") as f:
    for line in f.read().split("\n"):
        if line:
            install_requires.append(line)

# Get the long description from README.md
setup(
    name="mactopeer",
    version=__version__,

    packages=["pierky", "pierky.mactopeer"],
    namespace_packages=["pierky"],

    license="GPLv3",
    description="Automatically fetch MAC/IP address tables (ARP and IPv6 "
                "neighbors) from devices and build MAC address to BGP "
                "peer ASN mappings.",
    long_description=long_description,
    url="https://github.com/pierky/mactopeer",
    download_url="https://github.com/pierky/mactopeer",

    author="Pier Carlo Chiodi",
    author_email="pierky@pierky.com",
    maintainer="Pier Carlo Chiodi",
    maintainer_email="pierky@pierky.com",

    install_requires=install_requires,

    scripts=["scripts/mactopeer"],

    keywords=['BGP', 'IP Routing', 'pmacct', 'bgp_peer_src_as_map'],

    classifiers=[
        "Development Status :: 4 - Beta",

        "Environment :: Console",

        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",

        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",

        "Operating System :: POSIX",
        "Operating System :: Unix",

        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",

        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking",
    ]
)
