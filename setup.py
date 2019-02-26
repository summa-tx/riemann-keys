from setuptools import setup, find_packages

setup(
    name='riemann-keys',
    version='0.1.1',
    description=('Hierarchical deterministic wallet creation tool'),
    author=[
        "Harsha Goli",
        "James Prestwich",
        "RJ Rybarczyk",
        "Jarrett Wheatley"
        ],
    license="LGPLv3.0",
    install_requires=['riemann-secpy256k1==0.2.8'],
    packages=find_packages(),
    package_dir={'riemann_keys': 'riemann_keys'},
    keywords='bitcoin ethereum keys bip32 bip39 bip44'
)
