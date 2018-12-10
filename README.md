# HDKey: Fully functional python library for hierarchial deterministic key generation

Install from pypi for use in your project:
```
$ pip3 install hdkey
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
$ cd riemann_keys
$ pipenv install
$ pipenv install --dev
```

If a pip versioning error is encountered, try downgrading the local pip:
```
pipenv run pip install pip==18.0
```

## Test
```
$ pipenv run pytest
```

## Supported Networks
`Bitcoin` (default)  
`Testnet`  
`Litecoin`  
`Dogecoin`  
`Dash`  
`Ethereum`  

## User Documentation
Import `hdkey`:
```
from hdkey import HDKey
```

### Generate the root seed from a mnemonic

Args:  
&nbsp;&nbsp;&nbsp;&nbsp;`mnemonic` (str) a 12, 15, 18, 21, or 24 words from the [word list](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt)  
&nbsp;&nbsp;&nbsp;&nbsp;`network` (str) optional argument to specify the network (default is Bitcoin)  
&nbsp;&nbsp;&nbsp;&nbsp;`salt` (str) optional argument to add salt for added security  

Returns:  
    &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; (bytes) a 512-bit root seed  

```
MNEMONIC = "keen speed ice always runway film setup sentence update stove distance merge" 
root_seed = HDKey.root_seed_from_mnemonic(mnemonic=MNEMONIC)
```

### Generate a HDKey object from a root seed

Args:  
&nbsp;&nbsp;&nbsp;&nbsp;`root_seed` (bytes) 128, 256, or 215 bits in length   
&nbsp;&nbsp;&nbsp;&nbsp;`network` (str) optional argument to specify the network (default is Bitcoin)    

Returns:  
    &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; `HDKey` object  

```
root_seed = bytes.fromhex('26bad484f5a3f65ff827127133f314451218e0041aa6f1b68405ab78e3473e510734894f1f2906446b57b99ba4c2bd2b7206b729d95071a6cd801d61ca889dfa')
hdkey_obj = HDKey.from_root_seed(root_seed=root_seed, network='Bitcoin')
```
