## HDKey: HD Wallets for humans

HDKey is an implementation of bip32 HD Wallets using libsecp256k1 for signing, verification, and derivation.

### Installation, Development, & Running Tests

Install from pypi for use in your project:
```
$ pip3 install hdkey
# or 
$ pip3 install riemann-keys
```

## Development Setup (MacOsX)

Install pyenv:
```
$ brew update
$ brew install pyenv
$ env PYTHON_CONFIGURE_OPTS="--enable-framework" pyenv install 3.7.0
```

Install pipenv:
```
$ brew update
$ brew install pipenv
```

To use pyenv inconjuction with pipenv:
```
$ pipenv --python <path to pyenv python binary>
```
(Typically the path is `~/.pyenv/versions/3.7.0/bin/python3.7`)


## Development Install
```
$ git clone git@github.com:summa-tx/riemann-keys.git
$ cd riemann-keys
$ pipenv install
```

#### Install libsecp256k1 for development

HDKey requires libsecp256k1 to be installed on your system.

Full installation instructions are located here: [link](https://github.com/bitcoin-core/secp256k1)

```
$ git clone git@github.com:bitcoin-core/secp256k1.git
$ cd secp256k1
$ ./autogen.sh
$ ./configure
$ make
$ ./tests
$ sudo make install  # optional
```

#### Running tests

libsecp256k1 is required to run tests.

```
$ tox
```

### Usage

#### General

```Python
from riemann_keys import HDKey
my_key = HDKey.from_entropy(b'\x00' * 16)
print(my_key.xpriv)  # This is not actually a good idea

descendant = my_key.derive_path('m/44h/0h/0/0/0/7')
print(descendant.derive_child(79).path)    # m/44h/0h/0/0/0/7/79
print(descendant.derive_child('79h').path) # m/44h/0h/0/0/0/7/79h

msg = b'a messsage for signing'
sig = descendant.sign(msg)  # DER-encoded RFC6979 ECDSA sig

descendant.verify(sig=sig, msg=msg)  # return True or False
```

#### Instantiation
```Python
# From outside material
HDKey.from_xpub(xpub: str)           # an xpub
HDKey.from_xpriv(xpriv: str)         # an xpriv
HDKey.from_pubkey(pub: bytes)        # compressed pubkey
HDKey.from_privkey(priv: bytes)      # private key
HDKey.from_root_seed(seed: bytes)    # root seed
HDKey.from_entropy(entrpopy: bytes)  # bip39 entropy
HDKey.from_mnemonic(mnemonic: str)   # bip39 mnemonic

# child node derivation (requires chain code)
key_obj.derive_child(idx: int)  # child index eg. 7
key_obj.derive_child(idx: str)  # child index eg. '0h'
key_obj.derive_path(path: str)  # child path eg 'm/3/9h'
```


### Packaging in binaries

If you're looking to use `pyinstaller` to package, we strongly recommend using `pyenv` ([link](https://github.com/pyenv/pyenv)) to manage python installations. Make sure to build with `--enable-shared` or `--enable-framework` ([instructions here](https://github.com/pyenv/pyenv/wiki)) as appropriate.

We have tested `pyinstaller` with libsecp256k1 and HDKey on OSX and Linux.
