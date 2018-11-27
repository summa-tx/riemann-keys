
import hmac
import hashlib
import secpy256k1
import pkg_resources
from base58 import b58decode, b58encode


class HDKey:

    # NB: (bits of entropy, checksum bits, words in mnemonic)
    MNEMONIC_CODES = (
        (128, 4, 12),
        (160, 5, 15),
        (192, 6, 18),
        (224, 7, 21),
        (256, 8, 24),
    )

    # https://github.com/satoshilabs/slips/blob/master/slip-0044.md
    NETWORK_CODES = {
        "Bitcoin": 0,
        "Testnet": 1,
        "Litecoin": 2,
        "Dogecoin": 3,
        "Dash": 5,
        "Ethereum": 60,
    }

    # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
    VERSION_BYTES = {
        "mainnet": {
            "public": 0x0488B21E,
            "private": 0x0488ADE4,

        },
        "testnet": {
            "public": 0x043587CF,
            "private": 0x04358394,
        }
    }

    CONTEXT_SIGN = secpy256k1.context_create(
        secpy256k1.lib.SECP256K1_CONTEXT_SIGN
    )
    CONTEXT_VERIFY = secpy256k1.context_create(
        secpy256k1.lib.SECP256K1_CONTEXT_VERIFY
    )
    COMPRESSED = secpy256k1.lib.SECP256K1_EC_COMPRESSED

    def __init__(self, **kwargs):
        self._c_private_key = None,
        self._c_public_key = None
        self.child = None
        self.path = kwargs.get("path", "m")
        self.depth = kwargs.get("depth", 0)
        self.index = kwargs.get("index")
        self.network = kwargs.get("network", "Bitcoin")
        self.parent = kwargs.get("parent")
        self.chain_code = kwargs.get("chain_code")
        self.fingerprint = kwargs.get("fingerprint")
        # self.extended_private_key = kwargs.get("extended_private_key")

    @property
    def public_key(self):
        if self._c_public_key is None:
            return None

        c_public_key = secpy256k1.ec_pubkey_serialize(
            self.CONTEXT_VERIFY, self._c_public_key, self.COMPRESSED
        )[1]

        return self.convert_to_bytes(c_public_key)

    @public_key.setter
    def public_key(self, pubkey):
        if type(pubkey) != bytes:
            raise TypeError("Public key must be of type bytes")
        if len(pubkey) != 33 or len(pubkey) != 65:
            raise ValueError("Public key must be either 33 or 65 bytes")

        c_pubkey = secpy256k1.ec_pubkey_parse(self.CONTEXT_VERIFY, pubkey)[1]
        self._c_public_key = c_pubkey

    @property
    def private_key(self):
        if self._c_private_key is None:
            return None

        return self.convert_to_bytes(self._c_private_key, True)

    @private_key.setter
    def private_key(self, privkey):
        if type(privkey) != bytes:
            raise TypeError("Private key must be of type bytes")
        if len(privkey) != 32:
            raise ValueError("Private key must be 32 bytes")
        if secpy256k1.ec_seckey_verify(self.CONTEXT_SIGN, privkey) != 1:
            raise Exception("Secp256k1 verify failed")

        # store in c buffer
        c_private_key = secpy256k1.ffi.new("char[]", privkey)
        self._c_private_key = c_private_key

        # Derive public key from private
        c_unser_public_key = secpy256k1.ec_pubkey_create(
            ctx=self.CONTEXT_SIGN,
            seckey=privkey
        )[1]

        self._c_public_key = c_unser_public_key

    @property
    def extended_private_key(self):
        xpriv = b""
        if self.network == "Testnet":
            xpriv += b"\x04\x35\x83\x94"
        else:
            xpriv += b"\x04\x88\xAD\xE4"

        xpriv += bytes(chr(self.depth), 'utf8')
        xpriv += self.parent.fingerprint if self.parent else b"\x00\x00\x00\00"
        xpriv += int(self.index).to_bytes(4, byteorder="big")
        xpriv += self.chain_code
        xpriv += b"\x00" + self.private_key

        # checksum
        sha1 = hashlib.sha256(xpriv).digest()
        sha2 = hashlib.sha256(sha1).digest()
        xpriv += sha2[:4]

        return b58encode(xpriv).decode("utf-8")

    @extended_private_key.setter
    def extended_private_key(self, xpriv):
        if type(xpriv) != bytes:
            raise TypeError("Xpriv must be of type bytes")

        decoded_xpriv = b58decode(xpriv)
        if decoded_xpriv[:4] == b"\x04\x35\x83\x94":
            self.network = "Testnet"
        elif (decoded_xpriv[:4] == b"\x04\x88\xB2\x1E"
                or decoded_xpriv[:4] == b"\x04\x35\x87\xCF"):
            raise ValueError("Xpub provided instead of xpriv")

        self.depth = decoded_xpriv[4]
        self.fingerprint = decoded_xpriv[5:9]
        self.index = decoded_xpriv[9:13].hex()
        self.chain_code = decoded_xpriv[13:45]
        self.private_key = decoded_xpriv[46:79]

    @property
    def extended_public_key(self):
        xpub = b""
        if self.network == "Testnet":
            xpub += b"\x04\x35\x87\xCF"
        else:
            xpub += b"\x04\x88\xB2\x1E"

        xpub += bytes(chr(self.depth), 'utf8')
        xpub += self.parent.fingerprint if self.parent else b"\x00\x00\x00\00"
        xpub += int(self.index).to_bytes(4, byteorder="big")
        xpub += self.chain_code
        xpub += self.public_key

        # checksum
        sha1 = hashlib.sha256(xpub).digest()
        sha2 = hashlib.sha256(sha1).digest()
        xpub += sha2[:4]
        return b58encode(xpub).decode("utf-8")

    @extended_public_key.setter
    def extended_public_key(self, xpub):
        if type(xpub) != bytes:
            raise TypeError("Xpub must be of type bytes")

        decoded_xpub = b58decode(xpub)
        if decoded_xpub[:4] == b"\x04\x35\x87\xCF":
            self.network = "Testnet"
        elif (decoded_xpub[:4] == b"\x04\x88\xAD\xE4"
                or decoded_xpub[:4] == b"\x04\x35\x83\x94"):
            raise ValueError("Xpriv provided instead of xpub")

        self.depth = decoded_xpub[4]
        self.fingerprint = decoded_xpub[5:9]
        self.chain_code = decoded_xpub[13:45]
        self.public_key = decoded_xpub[45:78]

    @property
    def fingerprint(self):
        """ Returns fingerprint as 4 byte hex """
        if self._fingerprint is None:
            self._fingerprint = self.hash160(self.public_key)[:4]

        return self._fingerprint

    @fingerprint.setter
    def fingerprint(self, fingerprint):
        """ Stores fingerprint as bytes """
        if ((type(fingerprint) == bytes and len(fingerprint) == 4)
                or fingerprint is None):
            self._fingerprint = fingerprint
        elif type(fingerprint) == int:
            self._fingerprint = (fingerprint).to_bytes(4, byteorder='big')
        else:
            raise TypeError("Fingerprint must be either int or bytes")

    def derive_path(self, path):
        if len(path) == 0:
            return self
        if isinstance(path, str):
            path = path.split("/")

        assert path[-1] != '', "Malformed Path"

        current_node = path.pop(0)
        if (
            (
                current_node.lower() == "m"
                or current_node.lower() == "m'"
            )
            and len(path) == 0
        ):
            return self
        elif current_node.lower() == "m" or current_node.lower() == "m'":
            return self.derive_path(path)

        child = self.derive_child(current_node)
        child.path = self.path + "/" + str(current_node)
        child.parent = self
        self.child = child

        return child.derive_path(path)

    def derive_child(self, index):
        """
            Derives the immediate child to the index provided
            Args:
                index: (string)
            Returns:
                (HDKey)
        """
        hardened = False
        if "'" in index:
            index = int(index[:-1]) + 0x80000000  # 0x80000000 == 2^31,
            hardened = True

        index_serialized_32 = int(index).to_bytes(4, byteorder="big")

        if hardened:
            if (self.private_key is None):
                raise Exception(
                    "Private Key is needed for to derive hardened children"
                )

            # Data = 0x00 || ser256(kpar) || ser32(i)
            # (Note: The 0x00 pads the private key to make it 33 bytes long.)
            data = b"".join([b"\x00" + self.private_key, index_serialized_32])
        else:
            # Data = serP(point(kpar)) || ser32(i)).
            data = b"".join([self.public_key, index_serialized_32])

        # I = HMAC-SHA512(Key = cpar, Data)
        I = hmac.new(self.chain_code, digestmod=hashlib.sha512)
        I.update(data)
        I = I.digest()
        IL, IR = I[:32], I[32:]

        child = HDKey(
            parent=self,
            network=self.network,
            path=self.path + "/" + str(index),
            index=index,
            depth=self.depth + 1
        )

        # Private parent key -> private child key
        if self.private_key:
            check, child.private_key = secpy256k1.ec_privkey_tweak_add(
                ctx=self.CONTEXT_SIGN,
                seckey=self.private_key,
                tweak=IL
            )
            if (check == 0):
                # In case parse256(IL) ≥ n or ki = 0, the resulting key is
                # invalid, and one should proceed with the next value for i.
                # (Note: this has probability lower than 1 in 2^127.)
                return HDKey.derive_child(index + 1, hardened)

        # Public parent key -> public child key
        else:
            check, child.public_key = secpy256k1.ec_pubkey_tweak_add(
                ctx=self.CONTEXT_SIGN,
                pubkey=self.public_key,
                tweak=IL
            )
            if (check == 0):
                return HDKey.derive_child(index + 1, hardened)

        child.chain_code = IR
        return child

    @staticmethod
    def from_entropy(entropy, network='Bitcoin'):
        '''
        Generates a HDKey object given entropy.
        Args:
            entropy (bytes): 128, 160, 192, 224, or 256 bits
        Returns:
            (HDKey)
        '''
        # WIP
        HDKey.validate_entropy(entropy)

        # Generate mnemonic to get root seed
        mnemonic = HDKey.mnemonic_from_entropy(entropy)

        # Generate root seed to build HDKey
        root_seed = HDKey.root_seed_from_mnemonic(mnemonic, network)

        # Generate master keys and chain code from root_seed
        return HDKey.from_root_seed(root_seed, network)

    @staticmethod
    def from_root_seed(root_seed, network='Bitcoin'):
        '''
        Generates a HDKey object given the root seed.
        Args:
            root_seed (bytes):          128, 256, or 512 bits
            network (str, Optional):    Must be a selection from NETWORK_CODES,
                                        defaults to Bitcoin
        Returns:
            (HDKey)
        '''
        # WIP
        # TODO: get key depending on network
        # data/key, msg, digest
        I = hmac.new(                                                   # noqa: E741
            key=b'Bitcoin seed',
            msg=root_seed,
            digestmod=hashlib.sha512
        ).digest()

        # Private key, chain code
        I_left, I_right = I[:32], I[32:]

        root = HDKey(
            network=network,
            chain_code=I_right,
            depth=0,
            index=0,
            path='m/'
        )
        root.private_key = I_left
        return root

    @staticmethod
    def from_mnemonic(mnemonic, salt=None, network='Bitcon'):
        '''
        Generate a HDKey object given a mnemonic.
        Args:
            mnemonic    (str): 12, 15, 18, 21, 24 words from word list
            salt        (str): optional words for added security
            network (WIP)
        Returns:
            (HDKey)
        '''
        root_seed = HDKey.root_seed_from_mnemonic(mnemonic, salt, network)
        return HDKey.from_root_seed(root_seed, network)

    @staticmethod
    def mnemonic_from_entropy(entropy):
        '''Entropy -> Mnemonic.
        Args:
            entropy      (bytes): random 128, 160, 192, 224, or 256 bit string
            num_mnemonic (int): mnemonic length
        Returns:
            (str): generated mnemonic
        '''
        HDKey.validate_entropy(entropy)

        # Number of words in mnemonic
        num_mnemonic = HDKey.mnemonic_lookup(
            value=len(entropy) * 8,
            value_index=0,
            lookup_index=2
        )

        # Formatting to convert hex string to binary string
        bit_format = '0{}b'.format(len(entropy) * 8)

        # Convert hex string to binary string
        bit_string = format(int.from_bytes(entropy, 'big'), bit_format)

        # Append binary string with returned checksum digits
        bit_string += HDKey.checksum(entropy)

        # Number of segments to split bit_string
        segment_len = len(bit_string) // num_mnemonic

        # Split bit_string into segements, each index corresponding to a word
        segments = [
            int(bit_string[i:i + segment_len])
            for i in range(0, len(bit_string), segment_len)
        ]

        return ' '.join(HDKey.segments_to_mnemonic(segments))

    @staticmethod
    def segments_to_mnemonic(segments):
        '''Entropy + Checksum Bit Segments -> Mnemonic List.
        Args:
            segments    (list): random 128, 160, 192, 224, or 256 bit string
        Returns:
            (list): mnemonic list
        '''
        word_list = HDKey.import_word_list()
        index = list(map(lambda seg: int('0b' + str(seg), 2), segments))
        return list(map(lambda i: word_list[i], index))

    @staticmethod
    def root_seed_from_mnemonic(mnemonic, salt=None, network='Bitcoin'):
        '''Mnemoinc -> 512-bit root seed
        Generates the 512-bit seed as specified in BIP39 given a mnemonic.
        Args:
            mnemonic    (str): 12, 15, 18, 21, 24 words from word list
            salt        (str): optional words for added security
        Returns:
            (bytes): 512-bit root seed
        '''
        HDKey.validate_mnemonic(mnemonic)
        salt = 'mnemonic' + (salt if salt is not None else '')
        salt_bytes = salt.encode('utf-8')
        mnemonic_bytes = mnemonic.encode('utf-8')
        return hashlib.pbkdf2_hmac('sha512', mnemonic_bytes, salt_bytes, 2048)

    @staticmethod
    def mnemonic_to_bytes(mnemonic):
        '''Mnemonic -> [bytes]
        Args:
            mnemonic    (str): a 12, 15, 18, 21, or 24 word str
        Returns:
            (bytes): the entropy bytes
              (str): the checksum bits as an bitstring
        '''
        words = mnemonic.split()
        word_list = HDKey.import_word_list()
        segments = []

        # Convert from mnemonic to entropy + checksum bit-string
        for w in words:
            # Index of word in word list
            idx = word_list.index(w)
            # Map index to 11-bit value
            bits = '{0:011b}'.format(idx)
            # Append 11-bits to segments list
            segments.append(bits)

        # Entropy + checksum bits
        bit_string = ''.join(segments)

        # Number of checksum bits determined by number of words in mnemonic
        checksum_bits = HDKey.mnemonic_lookup(
            value=len(words), value_index=2, lookup_index=1)

        # Checksum bit-string (last bits at end of bit-string)
        checksum_idx = -1 * checksum_bits
        checksum_bits = bit_string[checksum_idx:]

        # Entropy bit-string
        bit_string = bit_string[:checksum_idx]

        # Entropy bit-string -> entropy bytes
        b = bytearray()
        for i in range(0, len(bit_string), 8):
            b.append(int(bit_string[i:i + 8], 2))

        return (bytes(b), checksum_bits)

    @staticmethod
    def mnemonic_lookup(value, value_index, lookup_index):
        '''MNEMONIC_CODES lookup.
        Args:
            value           (int): value to lookup in MNEMONIC_CODES tuple
            value_index     (int): value index of MNEMONIC_CODES tuple
            lookup_index    (int): lookup index of MNEMONIC_CODES tuple
        Returns:
            (int): found value in MNEMONIC_CODES tuple lookup_index
        '''
        # Check that entropy is of accepted type
        if not isinstance(value, int):
            raise ValueError('Mnemonic lookup value must be of integer type.')

        if not isinstance(value_index, int):
            raise ValueError('Mnemonic value index must be of integer type.')

        if not isinstance(lookup_index, int):
            raise ValueError('Mnemonic lookup index must be of integer type.')

        # Find corresponding entropy bit length nested tuple
        mnemonic_tuple = [
            num for num in HDKey.MNEMONIC_CODES if num[value_index] == value]

        if mnemonic_tuple:
            return mnemonic_tuple[0][lookup_index]

        raise ValueError(
            'Value {} not found in index {} of MNEMONIC_CODES.Value not in {}.'
            .format(
                value,
                value_index,
                ', '.join(
                    [str(num[value_index]) for num in HDKey.MNEMONIC_CODES])))

    @staticmethod
    def import_word_list():
        '''Imports BIP39 word list.
        Returns:
            (list): 2048 words specified in BIP39
        '''
        words = []

        # Import mnemonic words
        #  with open('./data/english.txt', 'r') as f:
        #      word_list = f.read()
        # Import mnemonic words
        word_list = pkg_resources.resource_string(
            'riemann_keys', 'data/english.txt').decode('utf-8')

        # Create mnemonic word list
        for word in word_list.split('\n')[:-1]:
            words.append(word)

        return words

    @staticmethod
    def validate_mnemonic(mnemonic):
        '''Validates a mnemonic
        Args:
            mnemonic    (string): potential mnemonic string
        Returns:
            (bool): true if the string is a valid mnemonic, otherwise false
        '''
        # Check the length
        mnem_lens = [c[2] for c in HDKey.MNEMONIC_CODES]
        split = mnemonic.split()
        words = HDKey.import_word_list()
        if len(split) not in mnem_lens:
            return False

        # Check each word against the list
        for word in split:
            if word not in words:
                return False

        # Check the checksum
        entropy_bytes, checksum = HDKey.mnemonic_to_bytes(mnemonic)
        if HDKey.checksum(entropy_bytes) != checksum:
            return False

        return True

    @staticmethod
    def checksum(entropy):
        '''Determine checksum and return first segment.
        Args:
            entropy     (bytes): random 128, 160, 192, 224, or 256 bit string
        Returns:
            (byte-str): First checksum segment to be appended to entropy
        '''
        HDKey.validate_entropy(entropy)

        checksum_len = HDKey.mnemonic_lookup(
                value=len(entropy) * 8,
                value_index=0,
                lookup_index=1)

        return format(int.from_bytes(
            hashlib.sha256(entropy).digest(), 'big'),
            '0256b')[:checksum_len]

    @staticmethod
    def validate_entropy(entropy):
        if not isinstance(entropy, bytes):
            raise ValueError('Entropy must be bytes.')

        len_e = len(entropy)
        if len_e not in list(map(lambda x: x // 8, [128, 160, 192, 224, 256])):
            raise ValueError('Entropy must be 16, 20, 24, 28, or 32 bytes.')

        return True

    @staticmethod
    def convert_to_bytes(key, pop_newline=False):
        byte_form = bytes(secpy256k1.ffi.buffer(key))
        if pop_newline:
            return byte_form[:-1]

        return byte_form

    @staticmethod
    def hash160(x):
        return hashlib.new('ripemd160', hashlib.sha256(x).digest()).digest()
