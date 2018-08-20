import base64
import hashlib
import hmac
from two1.bitcoin.utils import bytes_to_str
from two1.bitcoin.utils import address_to_key_hash
from two1.crypto.ecdsa import ECPointAffine
from two1.crypto.ecdsa import secp256k1

from hd.hd_key import HDKey
from hd.utils import get_bytes, sha3
from hd.signiture import Signature
from hd.hd_privatekey import HDPrivateKey, PrivateKey


bitcoin_curve = secp256k1()

class PublicKeyBase(object):
    """ Base class for both PublicKey and HDPublicKey.

    As this class is a base class it should not be used directly.

    Args:
        x (int): The x component of the public key point.
        y (int): The y component of the public key point.

    Returns:
        PublicKey: The object representing the public key.

    """

    @staticmethod
    def from_bytes(key_bytes):
        """ Generates a public key object from a byte (or hex) string.

        Args:
            key_bytes (bytes or str): A byte stream.

        Returns:
            PublicKey: A PublicKey object.
        """
        raise NotImplementedError

    @staticmethod
    def from_private_key(private_key):
        """ Generates a public key object from a PrivateKey object.

        Args:
            private_key (PrivateKey): The private key object from
               which to derive this object.

        Returns:
            PublicKey: A PublicKey object.
        """
        return private_key.public_key

    def __init__(self):
        pass

    def hash160(self, compressed=True):
        """ Return the RIPEMD-160 hash of the SHA-256 hash of the
        public key.

        Args:
            compressed (bool): Whether or not the compressed key should
               be used.
        Returns:
            bytes: RIPEMD-160 byte string.
        """
        raise NotImplementedError

    def address(self, compressed=True, testnet=False):
        """ Address property that returns the Base58Check
        encoded version of the HASH160.

        Args:
            compressed (bool): Whether or not the compressed key should
               be used.
            testnet (bool): Whether or not the key is intended for testnet
               usage. False indicates mainnet usage.

        Returns:
            bytes: Base58Check encoded string
        """
        raise NotImplementedError

    def verify(self, message, signature, do_hash=True):
        """ Verifies that message was appropriately signed.

        Args:
            message (bytes): The message to be verified.
            signature (Signature): A signature object.
            do_hash (bool): True if the message should be hashed prior
              to signing, False if not. This should always be left as
              True except in special situations which require doing
              the hash outside (e.g. handling Bitcoin bugs).

        Returns:
            verified (bool): True if the signature is verified, False
            otherwise.
        """
        raise NotImplementedError

    def to_hex(self):
        """ Hex representation of the serialized byte stream.

        Returns:
            h (str): A hex-encoded string.
        """
        return bytes_to_str(bytes(self))

    def __bytes__(self):
        raise NotImplementedError

    def __int__(self):
        raise NotImplementedError

    @property
    def compressed_bytes(self):
        """ Byte string corresponding to a compressed representation
        of this public key.

        Returns:
            b (bytes): A 33-byte long byte string.
        """
        raise NotImplementedError

class PublicKey(PublicKeyBase):
    """ Encapsulation of a Bitcoin ECDSA public key.

    This class provides a high-level API to using an ECDSA public
    key, specifically for Bitcoin (secp256k1) purposes.

    Args:
        x (int): The x component of the public key point.
        y (int): The y component of the public key point.

    Returns:
        PublicKey: The object representing the public key.
    """

    TESTNET_VERSION = 0x6F
    MAINNET_VERSION = 0x00

    @staticmethod
    def from_point(p):
        """ Generates a public key object from any object
        containing x, y coordinates.

        Args:
            p (Point): An object containing a two-dimensional, affine
               representation of a point on the secp256k1 curve.

        Returns:
            PublicKey: A PublicKey object.
        """
        return PublicKey(p.x, p.y)

    @staticmethod
    def from_int(i):
        """ Generates a public key object from an integer.

        Note:
            This assumes that the upper 32 bytes of the integer
            are the x component of the public key point and the
            lower 32 bytes are the y component.

        Args:
            i (Bignum): A 512-bit integer representing the public
               key point on the secp256k1 curve.

        Returns:
            PublicKey: A PublicKey object.
        """
        point = ECPointAffine.from_int(bitcoin_curve, i)
        return PublicKey.from_point(point)

    @staticmethod
    def from_base64(b64str, testnet=False):
        """ Generates a public key object from a Base64 encoded string.

        Args:
            b64str (str): A Base64-encoded string.
            testnet (bool) (Optional): If True, changes the version that
               is prepended to the key.

        Returns:
            PublicKey: A PublicKey object.
        """
        return PublicKey.from_bytes(base64.b64decode(b64str))

    @staticmethod
    def from_bytes(key_bytes):
        """ Generates a public key object from a byte (or hex) string.

        The byte stream must be of the SEC variety
        (http://www.secg.org/): beginning with a single byte telling
        what key representation follows. A full, uncompressed key
        is represented by: 0x04 followed by 64 bytes containing
        the x and y components of the point. For compressed keys
        with an even y component, 0x02 is followed by 32 bytes
        containing the x component. For compressed keys with an
        odd y component, 0x03 is followed by 32 bytes containing
        the x component.

        Args:
            key_bytes (bytes or str): A byte stream that conforms to the above.

        Returns:
            PublicKey: A PublicKey object.
        """
        b = get_bytes(key_bytes)
        key_bytes_len = len(b)

        key_type = b[0]
        if key_type == 0x04:
            # Uncompressed
            if key_bytes_len != 65:
                raise ValueError("key_bytes must be exactly 65 bytes long when uncompressed.")

            x = int.from_bytes(b[1:33], 'big')
            y = int.from_bytes(b[33:65], 'big')
        elif key_type == 0x02 or key_type == 0x03:
            if key_bytes_len != 33:
                raise ValueError("key_bytes must be exactly 33 bytes long when compressed.")

            x = int.from_bytes(b[1:33], 'big')
            ys = bitcoin_curve.y_from_x(x)

            # Pick the one that corresponds to key_type
            last_bit = key_type - 0x2
            for y in ys:
                if y & 0x1 == last_bit:
                    break
        else:
            return None

        return PublicKey(x, y)

    @staticmethod
    def from_hex(h):
        """ Generates a public key object from a hex-encoded string.

        See from_bytes() for requirements of the hex string.

        Args:
            h (str): A hex-encoded string.

        Returns:
            PublicKey: A PublicKey object.
        """
        return PublicKey.from_bytes(h)

    @staticmethod
    def from_signature(message, signature):
        """ Attempts to create PublicKey object by deriving it
        from the message and signature.

        Args:
            message (bytes): The message to be verified.
            signature (Signature): The signature for message.
               The recovery_id must not be None!

        Returns:
            PublicKey:
                A PublicKey object derived from the
                signature, it it exists. None otherwise.
        """
        if signature.recovery_id is None:
            raise ValueError("The signature must have a recovery_id.")

        msg = get_bytes(message)
        pub_keys = bitcoin_curve.recover_public_key(msg,
                                                    signature,
                                                    signature.recovery_id)

        for k, recid in pub_keys:
            if signature.recovery_id is not None and recid == signature.recovery_id:
                return PublicKey(k.x, k.y)

        return None

    @staticmethod
    def verify_bitcoin(message, signature, address):
        """ Verifies a message signed using PrivateKey.sign_bitcoin()
        or any of the bitcoin utils (e.g. bitcoin-cli, bx, etc.)

        Args:
            message(bytes): The message that the signature corresponds to.
            signature (bytes or str): A Base64 encoded signature
            address (str): Base58Check encoded address.

        Returns:
            bool: True if the signature verified properly, False otherwise.
        """
        magic_sig = base64.b64decode(signature)

        magic = magic_sig[0]
        sig = Signature.from_bytes(magic_sig[1:])
        sig.recovery_id = (magic - 27) & 0x3
        compressed = ((magic - 27) & 0x4) != 0

        # Build the message that was signed
        msg = b"\x18Bitcoin Signed Message:\n" + bytes([len(message)]) + message
        msg_hash = hashlib.sha256(msg).digest()

        derived_public_key = PublicKey.from_signature(msg_hash, sig)
        if derived_public_key is None:
            raise ValueError("Could not recover public key from the provided signature.")

        ver, h160 = address_to_key_hash(address)
        hash160 = derived_public_key.hash160(compressed)
        if hash160 != h160:
            return False

        return derived_public_key.verify(msg_hash, sig)

    def __init__(self, x, y):
        p = ECPointAffine(bitcoin_curve, x, y)
        if not bitcoin_curve.is_on_curve(p):
            raise ValueError("The provided (x, y) are not on the secp256k1 curve.")

        self.point = p

        # RIPEMD-160 of SHA-256
        r = hashlib.new('ripemd160')
        r.update(hashlib.sha256(bytes(self)).digest())
        self.ripe = r.digest()

        r = hashlib.new('ripemd160')
        r.update(hashlib.sha256(self.compressed_bytes).digest())
        self.ripe_compressed = r.digest()

        self.keccak = sha3(bytes(self)[1:])

    def hash160(self, compressed=True):
        """ Return the RIPEMD-160 hash of the SHA-256 hash of the
        public key.

        Args:
            compressed (bool): Whether or not the compressed key should
               be used.
        Returns:
            bytes: RIPEMD-160 byte string.
        """
        return self.ripe_compressed if compressed else self.ripe

    # def address(self, compressed=True):
    #     """ Address property that returns the Base58Check
    #     encoded version of the HASH160.

    #     Args:
    #         compressed (bool): Whether or not the compressed key should
    #            be used.

    #     Returns:
    #         bytes: Base58Check encoded string
    #     """
    #     return encode_hex(self.keccak[12:])

    def verify(self, message, signature, do_hash=True):
        """ Verifies that message was appropriately signed.

        Args:
            message (bytes): The message to be verified.
            signature (Signature): A signature object.
            do_hash (bool): True if the message should be hashed prior
              to signing, False if not. This should always be left as
              True except in special situations which require doing
              the hash outside (e.g. handling Bitcoin bugs).

        Returns:
            verified (bool): True if the signature is verified, False
            otherwise.
        """
        msg = get_bytes(message)
        return bitcoin_curve.verify(msg, signature, self.point, do_hash)

    def to_base64(self):
        """ Hex representation of the serialized byte stream.

        Returns:
            b (str): A Base64-encoded string.
        """
        return base64.b64encode(bytes(self))

    def __int__(self):
        mask = 2 ** 256 - 1
        return ((self.point.x & mask) << bitcoin_curve.nlen) | (self.point.y & mask)

    def __bytes__(self):
        return bytes(self.point)

    @property
    def compressed_bytes(self):
        """ Byte string corresponding to a compressed representation
        of this public key.

        Returns:
            b (bytes): A 33-byte long byte string.
        """
        return self.point.compressed_bytes

class HDPublicKey(HDKey, PublicKeyBase):
    """ Implements an HD Public Key according to BIP-0032:
    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

    For the vast majority of use cases, the static function
    HDPublicKey.from_parent() will be used rather than directly
    constructing an object.

    Args:
        x (int): x component of the point representing the public key.
        y (int): y component of the point representing the public key.
        chain_code (bytes): The chain code associated with the HD key.
        depth (int): How many levels below the master node this key is. By
           definition, depth = 0 for the master node.
        index (int): A value between 0 and 0xffffffff indicating the child
           number. Values >= 0x80000000 are considered hardened children.
        parent_fingerprint (bytes): The fingerprint of the parent node. This
           is 0x00000000 for the master node.

    Returns:
        HDPublicKey: An HDPublicKey object.

    """

    MAINNET_VERSION = 0x0488B21E
    TESTNET_VERSION = 0x043587CF

    @staticmethod
    def from_parent(parent_key, i):
        """
        """
        if isinstance(parent_key, HDPrivateKey):
            # Get child private key
            return HDPrivateKey.from_parent(parent_key, i).public_key
        elif isinstance(parent_key, HDPublicKey):
            if i & 0x80000000:
                raise ValueError("Can't generate a hardened child key from a parent public key.")
            else:
                I = hmac.new(parent_key.chain_code,
                             parent_key.compressed_bytes + i.to_bytes(length=4, byteorder='big'),
                             hashlib.sha512).digest()
                Il, Ir = I[:32], I[32:]
                parse_Il = int.from_bytes(Il, 'big')
                if parse_Il >= bitcoin_curve.n:
                    return None

                temp_priv_key = PrivateKey(parse_Il)
                Ki = temp_priv_key.public_key.point + parent_key._key.point
                if Ki.infinity:
                    return None

                child_depth = parent_key.depth + 1
                return HDPublicKey(x=Ki.x,
                                   y=Ki.y,
                                   chain_code=Ir,
                                   index=i,
                                   depth=child_depth,
                                   parent_fingerprint=parent_key.fingerprint)
        else:
            raise TypeError("parent_key must be either a HDPrivateKey or HDPublicKey object")

    def __init__(self, x, y, chain_code, index, depth,
                 parent_fingerprint=b'\x00\x00\x00\x00'):
        key = PublicKey(x, y)
        HDKey.__init__(self, key, chain_code, index, depth, parent_fingerprint)
        PublicKeyBase.__init__(self)

    @property
    def identifier(self):
        """ Returns the identifier for the key.

        A key's identifier and fingerprint are defined as:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers

        In this case, it will return the RIPEMD-160 hash of the
        non-extended public key.

        Returns:
            bytes: A 20-byte RIPEMD-160 hash.
        """
        return self.hash160()

    def hash160(self, compressed=True):
        """ Return the RIPEMD-160 hash of the SHA-256 hash of the
        non-extended public key.

        Note:
            This always returns the hash of the compressed version of
            the public key.

        Returns:
            bytes: RIPEMD-160 byte string.
        """
        return self._key.hash160(True)

    def address(self, compressed=True, testnet=False):
        """ Address property that returns the Base58Check
        encoded version of the HASH160.

        Args:
            compressed (bool): Whether or not the compressed key should
               be used.
            testnet (bool): Whether or not the key is intended for testnet
               usage. False indicates mainnet usage.

        Returns:
            bytes: Base58Check encoded string
        """
        return self._key.address(True)

    def verify(self, message, signature, do_hash=True):
        """ Verifies that message was appropriately signed.

        Args:
            message (bytes): The message to be verified.
            signature (Signature): A signature object.
            do_hash (bool): True if the message should be hashed prior
                to signing, False if not. This should always be left as
                True except in special situations which require doing
                the hash outside (e.g. handling Bitcoin bugs).

        Returns:
            verified (bool): True if the signature is verified, False
            otherwise.
        """
        return self._key.verify(message, signature, do_hash)

    @property
    def compressed_bytes(self):
        """ Byte string corresponding to a compressed representation
        of this public key.

        Returns:
            b (bytes): A 33-byte long byte string.
        """
        return self._key.compressed_bytes
