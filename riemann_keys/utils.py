import hashlib

from typing import Dict, Tuple

BIP32_HARDEN: int = 0x80000000

# NB: (bits of entropy, checksum bits, words in mnemonic)
MNEMONIC_CODES: Tuple[Tuple[int, int, int], ...] = (
    (128, 4, 12),
    (160, 5, 15),
    (192, 6, 18),
    (224, 7, 21),
    (256, 8, 24),
)

# https://github.com/satoshilabs/slips/blob/master/slip-0044.md
NETWORK_CODES: Dict[str, int] = {
    'Bitcoin': 0,
    'Testnet': 1,
    'Litecoin': 2,
    'Dogecoin': 3,
    'Dash': 5,
    'Ethereum': 60,
}

# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
VERSION_BYTES = {
    'mainnet': {
        'public': b'\x04\x88\xb2\x1e',
        'private': b'\x04\x88\xad\xe4',
    },
    'testnet': {
        'public': b'\x04\x35\x87\xcf',
        'private': b'\x04\x35\x83\x94',
    }
}


def rmd160(msg: bytes):  # pragma: nocover
    '''
    byte-like -> bytes
    '''
    h = hashlib.new('ripemd160')
    h.update(msg)
    return h.digest()


def sha256(msg: bytes):
    '''
    byte-like -> bytes
    '''
    return hashlib.sha256(msg).digest()


def hash160(msg: bytes):
    '''
    byte-like -> bytes
    '''
    h = hashlib.new('ripemd160')
    h.update(sha256(msg))
    return h.digest()


def hash256(msg: bytes):
    '''
    byte-like -> bytes
    '''
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()
