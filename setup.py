"""setup.py file."""
import uuid

from setuptools import setup, find_packages
try:
    from pip._internal.req import parse_requirements
except ImportError:
    from pip.req import parse_requirements

__author__ = 'Andreas Thienemann <andreas@bawue.net>'

install_reqs = parse_requirements('requirements.txt', session=uuid.uuid1())
reqs = [str(ir.req) for ir in install_reqs]

setup(
    name="napalm-procurve",
    version="0.5.0",
    packages=find_packages(),
    author="Andreas Thienemann",
    author_email="andreas@bawue.net",
    description="Network Automation and Programmability Abstraction Layer (NAPALM) ProCurve driver",
    long_description="ProCurve driver support for Napalm network automation.",
    classifiers=[
        'Topic :: Utilities',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/ixs/napalm-procurve",
    include_package_data=True,
    zip_safe=False,
    install_requires=reqs,
)
