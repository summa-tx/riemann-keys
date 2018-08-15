import base58
import base64
import random
import hashlib
import hmac
from mnemonic.mnemonic import Mnemonic

from two1.bitcoin.utils import bytes_to_str
from two1.bitcoin.utils import rand_bytes

from two1.crypto.ecdsa import secp256k1
from two1.crypto.ecdsa_base import Point


from hd_key import HDKey
from signiture import Signature
from hd_publickey import PublicKey, HDPublicKey
from utils import get_bytes

bitcoin_curve = secp256k1()
class PrivateKeyBase(object):

    
    """ Base class for both PrivateKey and HDPrivateKey.

    As this class is a base class it should not be used directly.

    Args:
        k (int): The private key.

    Returns:
        PrivateKey: The object representing the private key.
    """

    @staticmethod
    def from_b58check(private_key):
        """ Decodes a Base58Check encoded private-key.

        Args:
            private_key (str): A Base58Check encoded private key.

        Returns:
            PrivateKey: A PrivateKey object
        """
        raise NotImplementedError

    def __init__(self, k):
        self.key = k
        self._public_key = None

    @property
    def public_key(self):
        """ Returns the public key associated with this private key.

        Returns:
            PublicKey:
                The PublicKey object that corresponds to this
                private key.
        """
        return self._public_key

    def raw_sign(self, message, do_hash=True):
        """ Signs message using this private key.

        Args:
            message (bytes): The message to be signed. If a string is
               provided it is assumed the encoding is 'ascii' and
               converted to bytes. If this is not the case, it is up
               to the caller to convert the string to bytes
               appropriately and pass in the bytes.
            do_hash (bool): True if the message should be hashed prior
               to signing, False if not. This should always be left as
               True except in special situations which require doing
               the hash outside (e.g. handling Bitcoin bugs).

        Returns:
            ECPointAffine:
                a raw point (r = pt.x, s = pt.y) which is
                the signature.
        """
        raise NotImplementedError

    def sign(self, message, do_hash=True):
        """ Signs message using this private key.

        Note:
            This differs from `raw_sign()` since it returns a
            Signature object.

        Args:
            message (bytes or str): The message to be signed. If a
               string is provided it is assumed the encoding is
               'ascii' and converted to bytes. If this is not the
               case, it is up to the caller to convert the string to
               bytes appropriately and pass in the bytes.
            do_hash (bool): True if the message should be hashed prior
               to signing, False if not. This should always be left as
               True except in special situations which require doing
               the hash outside (e.g. handling Bitcoin bugs).

        Returns:
            Signature: The signature corresponding to message.
        """
        raise NotImplementedError

    def sign_bitcoin(self, message, compressed=False):
        """ Signs a message using this private key such that it
        is compatible with bitcoind, bx, and other Bitcoin
        clients/nodes/utilities.

        Note:
            0x18 + b\"Bitcoin Signed Message:" + newline + len(message) is
            prepended to the message before signing.

        Args:
            message (bytes or str): Message to be signed.
            compressed (bool): True if the corresponding public key will be
              used in compressed format. False if the uncompressed version
              is used.

        Returns:
            bytes: A Base64-encoded byte string of the signed message.
            The first byte of the encoded message contains information
            about how to recover the public key. In bitcoind parlance,
            this is the magic number containing the recovery ID and
            whether or not the key was compressed or not. (This function
            always processes full, uncompressed public-keys, so the magic
            number will always be either 27 or 28).
        """
        raise NotImplementedError

    def to_b58check(self, testnet=False):
        """ Generates a Base58Check encoding of this private key.

        Returns:
            str: A Base58Check encoded string representing the key.
        """
        raise NotImplementedError

    def to_hex(self):
        """ Generates a hex encoding of the serialized key.

        Returns:
           str: A hex encoded string representing the key.
        """
        return bytes_to_str(bytes(self))

    def __bytes__(self):
        raise NotImplementedError

    def __int__(self):
        raise NotImplementedError


class PrivateKey(PrivateKeyBase):
    """ Encapsulation of a Bitcoin ECDSA private key.

    This class provides capability to generate private keys,
    obtain the corresponding public key, sign messages and
    serialize/deserialize into a variety of formats.

    Args:
        k (int): The private key.

    Returns:
        PrivateKey: The object representing the private key.
    """
    TESTNET_VERSION = 0xEF
    MAINNET_VERSION = 0x80

    @staticmethod
    def from_bytes(b):
        """ Generates PrivateKey from the underlying bytes.

        Args:
            b (bytes): A byte stream containing a 256-bit (32-byte) integer.

        Returns:
            tuple(PrivateKey, bytes): A PrivateKey object and the remainder
            of the bytes.
        """
        if len(b) < 32:
            raise ValueError('b must contain at least 32 bytes')

        return PrivateKey(int.from_bytes(b[:32], 'big'))

    @staticmethod
    def from_hex(h):
        """ Generates PrivateKey from a hex-encoded string.

        Args:
            h (str): A hex-encoded string containing a 256-bit
                 (32-byte) integer.

        Returns:
            PrivateKey: A PrivateKey object.
        """
        return PrivateKey.from_bytes(bytes.fromhex(h))

    @staticmethod
    def from_int(i):
        """ Initializes a private key from an integer.

        Args:
            i (int): Integer that is the private key.

        Returns:
            PrivateKey: The object representing the private key.
        """
        return PrivateKey(i)

    @staticmethod
    def from_b58check(private_key):
        """ Decodes a Base58Check encoded private-key.

        Args:
            private_key (str): A Base58Check encoded private key.

        Returns:
            PrivateKey: A PrivateKey object
        """
        b58dec = base58.b58decode_check(private_key)
        version = b58dec[0]
        assert version in [PrivateKey.TESTNET_VERSION,
                           PrivateKey.MAINNET_VERSION]

        return PrivateKey(int.from_bytes(b58dec[1:], 'big'))

    @staticmethod
    def from_random():
        """ Initializes a private key from a random integer.

        Returns:
            PrivateKey: The object representing the private key.
        """
        return PrivateKey(random.SystemRandom().randrange(1, bitcoin_curve.n))

    def __init__(self, k):
        self.key = k
        self._public_key = None

    @property
    def public_key(self):
        """ Returns the public key associated with this private key.

        Returns:
            PublicKey:
                The PublicKey object that corresponds to this
                private key.
        """
        if self._public_key is None:
            self._public_key = PublicKey.from_point(
                bitcoin_curve.public_key(self.key))
        return self._public_key

    def raw_sign(self, message, do_hash=True):
        """ Signs message using this private key.

        Args:
            message (bytes): The message to be signed. If a string is
                provided it is assumed the encoding is 'ascii' and
                converted to bytes. If this is not the case, it is up
                to the caller to convert the string to bytes
                appropriately and pass in the bytes.
            do_hash (bool): True if the message should be hashed prior
                to signing, False if not. This should always be left as
                True except in special situations which require doing
                the hash outside (e.g. handling Bitcoin bugs).

        Returns:
            ECPointAffine:
                a raw point (r = pt.x, s = pt.y) which is
                the signature.
        """
        if isinstance(message, str):
            msg = bytes(message, 'ascii')
        elif isinstance(message, bytes):
            msg = message
        else:
            raise TypeError("message must be either str or bytes!")

        sig_pt, rec_id = bitcoin_curve.sign(msg, self.key, do_hash)

        # Take care of large s:
        # Bitcoin deals with large s, by subtracting
        # s from the curve order. See:
        # https://bitcointalk.org/index.php?topic=285142.30;wap2
        if sig_pt.y >= (bitcoin_curve.n // 2):
            sig_pt = Point(sig_pt.x, bitcoin_curve.n - sig_pt.y)
            rec_id ^= 0x1

        return (sig_pt, rec_id)

    def sign(self, message, do_hash=True):
        """ Signs message using this private key.

        Note:
            This differs from `raw_sign()` since it returns a Signature object.

        Args:
            message (bytes or str): The message to be signed. If a
                string is provided it is assumed the encoding is
                'ascii' and converted to bytes. If this is not the
                case, it is up to the caller to convert the string to
                bytes appropriately and pass in the bytes.
            do_hash (bool): True if the message should be hashed prior
                to signing, False if not. This should always be left as
                True except in special situations which require doing
                the hash outside (e.g. handling Bitcoin bugs).

        Returns:
            Signature: The signature corresponding to message.
        """
        # Some BTC things want to have the recovery id to extract the public
        # key, so we should figure that out.
        sig_pt, rec_id = self.raw_sign(message, do_hash)

        return Signature(sig_pt.x, sig_pt.y, rec_id)

    def sign_bitcoin(self, message, compressed=False):
        """ Signs a message using this private key such that it
        is compatible with bitcoind, bx, and other Bitcoin
        clients/nodes/utilities.

        Note:
            0x18 + b\"Bitcoin Signed Message:" + newline + len(message) is
            prepended to the message before signing.

        Args:
            message (bytes or str): Message to be signed.
            compressed (bool): True if the corresponding public key will be
              used in compressed format. False if the uncompressed version
              is used.

        Returns:
            bytes: A Base64-encoded byte string of the signed message.
            The first byte of the encoded message contains information
            about how to recover the public key. In bitcoind parlance,
            this is the magic number containing the recovery ID and
            whether or not the key was compressed or not.
        """
        if isinstance(message, str):
            msg_in = bytes(message, 'ascii')
        elif isinstance(message, bytes):
            msg_in = message
        else:
            raise TypeError("message must be either str or bytes!")

        msg = b"\x18Bitcoin Signed Message:\n" + bytes([len(msg_in)]) + msg_in
        msg_hash = hashlib.sha256(msg).digest()

        sig = self.sign(msg_hash)
        comp_adder = 4 if compressed else 0
        magic = 27 + sig.recovery_id + comp_adder

        return base64.b64encode(bytes([magic]) + bytes(sig))

    def to_b58check(self, testnet=False):
        """ Generates a Base58Check encoding of this private key.

        Returns:
            str: A Base58Check encoded string representing the key.
        """
        version = self.TESTNET_VERSION if testnet else self.MAINNET_VERSION
        return base58.b58encode_check(bytes([version]) + bytes(self))

    def __bytes__(self):
        return self.key.to_bytes(32, 'big')

    def __int__(self):
        return self.key


class HDPrivateKey(HDKey, PrivateKeyBase):
    """ Implements an HD Private Key according to BIP-0032:
    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

    For the vast majority of use cases, the 3 static functions
    (HDPrivateKey.master_key_from_entropy,
    HDPrivateKey.master_key_from_seed and
    HDPrivateKey.from_parent) will be used rather than directly
    constructing an object.

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
    MAINNET_VERSION = 0x0488ADE4
    TESTNET_VERSION = 0x04358394

    @staticmethod
    def master_key_from_mnemonic(mnemonic, passphrase=''):
        """ Generates a master key from a mnemonic.

        Args:
            mnemonic (str): The mnemonic sentence representing
               the seed from which to generate the master key.
            passphrase (str): Password if one was used.

        Returns:
            HDPrivateKey: the master private key.
        """
        return HDPrivateKey.master_key_from_seed(
            Mnemonic.to_seed(mnemonic, passphrase))

    @staticmethod
    def master_key_from_entropy(passphrase='', strength=128):
        """ Generates a master key from system entropy.

        Args:
            strength (int): Amount of entropy desired. This should be
               a multiple of 32 between 128 and 256.
            passphrase (str): An optional passphrase for the generated
               mnemonic string.

        Returns:
            HDPrivateKey, str:
                a tuple consisting of the master
                private key and a mnemonic string from which the seed
                can be recovered.
        """
        if strength % 32 != 0:
            raise ValueError("strength must be a multiple of 32")
        if strength < 128 or strength > 256:
            raise ValueError("strength should be >= 128 and <= 256")
        entropy = rand_bytes(strength // 8)
        m = Mnemonic(language='english')
        n = m.to_mnemonic(entropy)
        return HDPrivateKey.master_key_from_seed(
            Mnemonic.to_seed(n, passphrase)), n

    @staticmethod
    def master_key_from_seed(seed):
        """ Generates a master key from a provided seed.

        Args:
            seed (bytes or str): a string of bytes or a hex string

        Returns:
            HDPrivateKey: the master private key.
        """
        S = get_bytes(seed)
        I = hmac.new(b"Bitcoin seed", S, hashlib.sha512).digest()
        Il, Ir = I[:32], I[32:]
        parse_Il = int.from_bytes(Il, 'big')
        if parse_Il == 0 or parse_Il >= bitcoin_curve.n:
            raise ValueError("Bad seed, resulting in invalid key!")

        return HDPrivateKey(key=parse_Il, chain_code=Ir, index=0, depth=0)

    @staticmethod
    def from_parent(parent_key, i):
        """ Derives a child private key from a parent
        private key. It is not possible to derive a child
        private key from a public parent key.

        Args:
            parent_private_key (HDPrivateKey):
        """
        if not isinstance(parent_key, HDPrivateKey):
            raise TypeError("parent_key must be an HDPrivateKey object.")

        hmac_key = parent_key.chain_code
        if i & 0x80000000:
            hmac_data = b'\x00' + bytes(parent_key._key) + i.to_bytes(length=4, byteorder='big')
        else:
            hmac_data = parent_key.public_key.compressed_bytes + i.to_bytes(length=4, byteorder='big')

        I = hmac.new(hmac_key, hmac_data, hashlib.sha512).digest()
        Il, Ir = I[:32], I[32:]

        parse_Il = int.from_bytes(Il, 'big')
        if parse_Il >= bitcoin_curve.n:
            return None

        child_key = (parse_Il + parent_key._key.key) % bitcoin_curve.n

        if child_key == 0:
            # Incredibly unlucky choice
            return None

        child_depth = parent_key.depth + 1
        return HDPrivateKey(key=child_key,
                            chain_code=Ir,
                            index=i,
                            depth=child_depth,
                            parent_fingerprint=parent_key.fingerprint)

    def __init__(self, key, chain_code, index, depth,
                 parent_fingerprint=b'\x00\x00\x00\x00'):
        if index < 0 or index > 0xffffffff:
            raise ValueError("index is out of range: 0 <= index <= 2**32 - 1")

        private_key = PrivateKey(key)
        HDKey.__init__(self, private_key, chain_code, index, depth,
                       parent_fingerprint)
        self._public_key = None

    @property
    def public_key(self):
        """ Returns the public key associated with this private key.

        Returns:
            HDPublicKey:
                The HDPublicKey object that corresponds to this
                private key.
        """
        if self._public_key is None:
            self._public_key = HDPublicKey(x=self._key.public_key.point.x,
                                           y=self._key.public_key.point.y,
                                           chain_code=self.chain_code,
                                           index=self.index,
                                           depth=self.depth,
                                           parent_fingerprint=self.parent_fingerprint)

        return self._public_key

    def raw_sign(self, message, do_hash=True):
        """ Signs message using the underlying non-extended private key.

        Args:
            message (bytes): The message to be signed. If a string is
                provided it is assumed the encoding is 'ascii' and
                converted to bytes. If this is not the case, it is up
                to the caller to convert the string to bytes
                appropriately and pass in the bytes.
            do_hash (bool): True if the message should be hashed prior
                to signing, False if not. This should always be left as
                True except in special situations which require doing
                the hash outside (e.g. handling Bitcoin bugs).

        Returns:
            ECPointAffine:
                a raw point (r = pt.x, s = pt.y) which is
                the signature.
        """
        return self._key.raw_sign(message, do_hash)

    def sign(self, message, do_hash=True):
        """ Signs message using the underlying non-extended private key.

        Note:
            This differs from `raw_sign()` since it returns a Signature object.

        Args:
            message (bytes or str): The message to be signed. If a
                string is provided it is assumed the encoding is
                'ascii' and converted to bytes. If this is not the
                case, it is up to the caller to convert the string to
                bytes appropriately and pass in the bytes.
            do_hash (bool): True if the message should be hashed prior
                to signing, False if not. This should always be left as
                True except in special situations which require doing
                the hash outside (e.g. handling Bitcoin bugs).

        Returns:
            Signature: The signature corresponding to message.
        """
        return self._key.sign(message, do_hash)

    def sign_bitcoin(self, message, compressed=False):
        """ Signs a message using the underlying non-extended private
        key such that it is compatible with bitcoind, bx, and other
        Bitcoin clients/nodes/utilities.

        Note:
            0x18 + b\"Bitcoin Signed Message:" + newline + len(message) is
            prepended to the message before signing.

        Args:
            message (bytes or str): Message to be signed.
            compressed (bool):
                True if the corresponding public key will be
                used in compressed format. False if the uncompressed version
                is used.

        Returns:
            bytes: A Base64-encoded byte string of the signed message.
            The first byte of the encoded message contains information
            about how to recover the public key. In bitcoind parlance,
            this is the magic number containing the recovery ID and
            whether or not the key was compressed or not. (This function
            always processes full, uncompressed public-keys, so the
            magic number will always be either 27 or 28).
        """

        return self._key.sign_bitcoin(message, compressed)

    @property
    def identifier(self):
        """ Returns the identifier for the key.

        A key's identifier and fingerprint are defined as:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers

        In this case, it will return the RIPEMD-160 hash of the
        corresponding public key.

        Returns:
            bytes: A 20-byte RIPEMD-160 hash.
        """
        return self.public_key.hash160()

    def __int__(self):
        return int(self.key)
