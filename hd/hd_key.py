from utils import sha3, get_bytes
from hd_privatekey import HDPrivateKey
from hd_publickey import HDPublicKey, PublicKey

class HDKey(object):
    """ Base class for HDPrivateKey and HDPublicKey.

    Args:
        key (PrivateKey or PublicKey): The underlying simple private or
           public key that is used to sign/verify.
        chain_code (bytes): The chain code associated with the HD key.
        depth (int): How many levels below the master node this key is. By
           definition, depth = 0 for the master node.
        index (int): A value between 0 and 0xffffffff indicating the child
           number. Values >= 0x80000000 are considered hardened children.
        parent_fingerprint (bytes): The fingerprint of the parent node. This
           is 0x00000000 for the master node.

    Returns:
        HDKey: An HDKey object.
    """
    @staticmethod
    def from_b58check(key):
        """ Decodes a Base58Check encoded key.

        The encoding must conform to the description in:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format

        Args:
            key (str): A Base58Check encoded key.

        Returns:
            HDPrivateKey or HDPublicKey:
                Either an HD private or
                public key object, depending on what was serialized.
        """
        return HDKey.from_bytes(base58.b58decode_check(key))

    @staticmethod
    def from_bytes(b):
        """ Generates either a HDPrivateKey or HDPublicKey from the underlying
        bytes.

        The serialization must conform to the description in:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format

        Args:
            b (bytes): A byte stream conforming to the above.

        Returns:
            HDPrivateKey or HDPublicKey:
                Either an HD private or
                public key object, depending on what was serialized.
        """
        if len(b) < 78:
            raise ValueError("b must be at least 78 bytes long.")

        version = int.from_bytes(b[:4], 'big')
        depth = b[4]
        parent_fingerprint = b[5:9]
        index = int.from_bytes(b[9:13], 'big')
        chain_code = b[13:45]
        key_bytes = b[45:78]

        rv = None
        if version == HDPrivateKey.MAINNET_VERSION or version == HDPrivateKey.TESTNET_VERSION:
            if key_bytes[0] != 0:
                raise ValueError("First byte of private key must be 0x00!")

            private_key = int.from_bytes(key_bytes[1:], 'big')
            rv = HDPrivateKey(key=private_key,
                              chain_code=chain_code,
                              index=index,
                              depth=depth,
                              parent_fingerprint=parent_fingerprint)
        elif version == HDPublicKey.MAINNET_VERSION or version == HDPublicKey.TESTNET_VERSION:
            if key_bytes[0] != 0x02 and key_bytes[0] != 0x03:
                raise ValueError("First byte of public key must be 0x02 or 0x03!")

            public_key = PublicKey.from_bytes(key_bytes)
            rv = HDPublicKey(x=public_key.point.x,
                             y=public_key.point.y,
                             chain_code=chain_code,
                             index=index,
                             depth=depth,
                             parent_fingerprint=parent_fingerprint)
        else:
            raise ValueError("incorrect encoding.")

        return rv

    @staticmethod
    def from_hex(h):
        """ Generates either a HDPrivateKey or HDPublicKey from the underlying
        hex-encoded string.

        The serialization must conform to the description in:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format

        Args:
            h (str): A hex-encoded string conforming to the above.

        Returns:
            HDPrivateKey or HDPublicKey:
                Either an HD private or
                public key object, depending on what was serialized.
        """
        return HDKey.from_bytes(bytes.fromhex(h))

    @staticmethod
    def from_path(root_key, path):
        p = HDKey.parse_path(path)

        if p[0] == "m":
            if root_key.master:
                p = p[1:]
            else:
                raise ValueError("root_key must be a master key if 'm' is the first element of the path.")

        keys = [root_key]
        for i in p:
            if isinstance(i, str):
                hardened = i[-1] == "'"
                index = int(i[:-1], 0) | 0x80000000 if hardened else int(i, 0)
            else:
                index = i
            k = keys[-1]
            klass = k.__class__
            keys.append(klass.from_parent(k, index))

        return keys

    @staticmethod
    def parse_path(path):
        if isinstance(path, str):
            # Remove trailing "/"
            p = path.rstrip("/").split("/")
        elif isinstance(path, bytes):
            p = path.decode('utf-8').rstrip("/").split("/")
        else:
            p = list(path)

        return p

    @staticmethod
    def path_from_indices(l):
        p = []
        for n in l:
            if n == "m":
                p.append(n)
            else:
                if n & 0x80000000:
                    _n = n & 0x7fffffff
                    p.append(str(_n) + "'")
                else:
                    p.append(str(n))

        return "/".join(p)

    def __init__(self, key, chain_code, index, depth, parent_fingerprint):
        if index < 0 or index > 0xffffffff:
            raise ValueError("index is out of range: 0 <= index <= 2**32 - 1")

        if not isinstance(chain_code, bytes):
            raise TypeError("chain_code must be bytes")

        self._key = key
        self.chain_code = chain_code
        self.depth = depth
        self.index = index

        self.parent_fingerprint = get_bytes(parent_fingerprint)

    @property
    def master(self):
        """ Whether or not this is a master node.

        Returns:
            bool: True if this is a master node, False otherwise.
        """
        return self.depth == 0

    @property
    def hardened(self):
        """ Whether or not this is a hardened node.

        Hardened nodes are those with indices >= 0x80000000.

        Returns:
            bool: True if this is hardened, False otherwise.
        """
        # A hardened key is a key with index >= 2 ** 31, so
        # we check that the MSB of a uint32 is set.
        return self.index & 0x80000000

    @property
    def identifier(self):
        """ Returns the identifier for the key.

        A key's identifier and fingerprint are defined as:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers

        Returns:
            bytes: A 20-byte RIPEMD-160 hash.
        """
        raise NotImplementedError

    @property
    def fingerprint(self):
        """ Returns the key's fingerprint, which is the first 4 bytes
        of its identifier.

        A key's identifier and fingerprint are defined as:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers

        Returns:
            bytes: The first 4 bytes of the RIPEMD-160 hash.
        """
        return self.identifier[:4]

    def to_b58check(self, testnet=False):
        """ Generates a Base58Check encoding of this key.

        Args:
            testnet (bool): True if the key is to be used with
                testnet, False otherwise.
        Returns:
            str: A Base58Check encoded string representing the key.
        """
        b = self.testnet_bytes if testnet else bytes(self)
        return base58.b58encode_check(b)

    def _serialize(self, testnet=False):
        version = self.TESTNET_VERSION if testnet else self.MAINNET_VERSION
        key_bytes = self._key.compressed_bytes if isinstance(self, HDPublicKey) else b'\x00' + bytes(self._key)
        return (version.to_bytes(length=4, byteorder='big') +
                bytes([self.depth]) +
                self.parent_fingerprint +
                self.index.to_bytes(length=4, byteorder='big') +
                self.chain_code +
                key_bytes)

    def __bytes__(self):
        return self._serialize()

    @property
    def testnet_bytes(self):
        """ Serialization of the key for testnet.

        Returns:
            bytes:
                A 78-byte serialization of the key, specifically for
                testnet (i.e. the first 2 bytes will be 0x0435).
        """
        return self._serialize(True)
