# flake8: noqa

from setuptools import setup, find_packages

authors = [
    "Harsha Goli",
    "James Prestwich",
    "RJ Rybarczyk",
    "Jarrett Wheatley"
]

setup(
    name='riemann-keys',
    version='0.1.2',
    url='https://github.com/summa-tx/riemann-keys',
    description=('Hierarchical deterministic wallet creation tool'),
    author=authors,
    author_email='james@summa.one',
    install_requires=['riemann-secpy256k1==0.2.8'],
    packages=find_packages(),
    package_dir={'riemann_keys': 'riemann_keys'},
    keywords='bitcoin ethereum keys bip32 bip39 bip44',
    classifiers=[
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)'
    ]
)
