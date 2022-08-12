from setuptools import setup, find_packages
from os.path import join, dirname

version = '0.1.0'
readme = open(join(dirname(__file__), 'README.md')).read()
packages = find_packages(exclude=['tests'])

setup(
    name='ton_connect',
    version=version,
    packages=packages,
    long_description=readme,
    python_requires='>=3.7',
    install_requires=[
        'pynacl==1.5.0',
        'tvm-valuetypes==0.0.9'
    ],
)
