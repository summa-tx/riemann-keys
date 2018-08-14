from Crypto.Hash import keccak
sha3_256 = lambda x: keccak.new(digest_bits=256, data=x)


def sha3(seed):
    return sha3_256(seed).digest()

def get_bytes(s):
    """Returns the byte representation of a hex- or byte-string."""
    if isinstance(s, bytes):
        b = s
    elif isinstance(s, str):
        b = bytes.fromhex(s)
    else:
        raise TypeError("s must be either 'bytes' or 'str'!")

    return b