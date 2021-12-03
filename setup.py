"""setup.py file."""
import uuid

from setuptools import setup, find_packages
try:
    # pip >=20
    from pip._internal.network.session import PipSession
except ImportError:
    try:
        # 10.0.0 <= pip <= 19.3.1
        from pip._internal.download import PipSession
    except ImportError:
        # pip <= 9.0.3
        from pip.download import PipSession

def parse_requirements(filename):
    """ load requirements from a pip requirements file """
    lines = (line.strip() for line in open(filename))
    return [line for line in lines if line and not line.startswith("#")]

__author__ = 'Andreas Thienemann <andreas@bawue.net>'

reqs = parse_requirements('requirements.txt')

setup(
    name="napalm-procurve",
    version="0.7.0",
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
