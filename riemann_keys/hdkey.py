
import hmac
import hashlib
import secpy256k1
from riemann_keys import utils
import pkg_resources

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

    SECP256K1_CONTEXT_SIGN = secpy256k1.context_create(secpy256k1.lib.SECP256K1_CONTEXT_SIGN)
    SECP256K1_EC_COMPRESSED = secpy256k1.lib.SECP256K1_EC_COMPRESSED

    def __init__(self, path, depth=0, index=None, network="Bitcoin", parent=None, chain_code=None, private_key=None, public_key=None, fingerprint=None):
        self._public_key = None
        self._private_key = None
        self.path = path
        self.depth = depth
        self.index = index
        self.network = network
        self.parent = parent
        self.chain_code = chain_code
        self._private_key = private_key
        self._public_key = public_key
        self.fingerprint = fingerprint

    @property
    def public_key(self):
        return self._public_key
    
    @public_key.setter
    def public_key(self, pubkey):
        assert type(pubkey) == bytes, "Public key must be of type bytes"
        assert len(pubkey) == 33 or len(pubkey) == 65, "Public key must be either 33 or 65 bytes"
        #TODO ECDSA sig verify

        self._public_key = pubkey

    @property
    def private_key(self):
        return self._private_key

    @private_key.setter
    def private_key(self, privkey):
        assert type(privkey) == bytes, "Private key must be of type bytes"
        assert len(privkey) == 32, "Private key must be 32 bytes"
        assert secpy256k1.ec_seckey_verify(self.SECP256K1_CONTEXT_SIGN, privkey) == 1, "secp256k1 verify failed"

        self._private_key = privkey

        check, c_unserialized_public_key = secpy256k1.ec_pubkey_create(ctx=self.SECP256K1_CONTEXT_SIGN, seckey=privkey)
        check, c_public_key, c_public_key_length = secpy256k1.ec_pubkey_serialize(self.SECP256K1_CONTEXT_SIGN, c_unserialized_public_key, self.SECP256K1_EC_COMPRESSED)
        pubkey = self.convert_to_bytes(c_public_key)

        if self._public_key != None:
            assert self.public_key == pubkey, "Private key does not match current public key"
        
        self.public_key = pubkey

    @property
    def extended_private_key(self):
        return

    @extended_private_key.setter
    def extended_private_key(self, xpriv):
        return

    @property
    def extended_public_key(self):
        return

    @extended_public_key.setter
    def extended_public_key(self, xpub):
        return
        
    def derive_path(self, path):
        if len(path) == 0:
            return self

        if isinstance(path, str):
            path = path.split("/")

        assert path[-1] != '', "Malformed Path"

        current_node = path.pop(0)
        if (current_node.lower() == "m" or current_node.lower() == "m'") and len(path) == 0:
            return self
        elif current_node.lower() == "m" or current_node.lower() == "m'":
            return self.derive_path(path)

        child = self.derive_child(current_node)
        child.parent = self

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

        index_serialized_32_bits = int(index).to_bytes(4, byteorder="big")

        if hardened:
            assert (self.private_key), "Private Key is needed for to derive hardened children"

            # Data = 0x00 || ser256(kpar) || ser32(i) (Note: The 0x00 pads the private key to make it 33 bytes long.)
            data = b"".join([self.private_key, index_serialized_32_bits])
        else:
            # Data = serP(point(kpar)) || ser32(i)).
            data = b"".join([self.public_key, index_serialized_32_bits])

        # I = HMAC-SHA512(Key = cpar, Data)
        I = hmac.new(self.chain_code, digestmod=hashlib.sha512)
        I.update(data)
        I = I.digest()
        IL, IR = I[:32], I[32:]

        child = HDKey(parent=self, network=self.network, path=self.path + "/" + str(index), index=index, depth=self.depth + 1)

        # Private parent key -> private child key
        if self.private_key:
            check, child.private_key = secpy256k1.ec_privkey_tweak_add(ctx=self.SECP256K1_CONTEXT_SIGN, seckey=self.private_key, tweak=IL)
            if (check == 0):
                # In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid, and one should proceed with the next value for i. 
                # (Note: this has probability lower than 1 in 2^127.)
                return HDKey.derive_child(index + 1, hardened)
    
        # Public parent key -> public child key
        else:
            check, child.public_key = secpy256k1.ec_pubkey_tweak_add(ctx=self.SECP256K1_CONTEXT_SIGN, pubkey=self.public_key, tweak=IL)
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
            root_seed (bytes): 128, 256, or 512 bits
            network (str, Optional): Must be a selection from NETWORK_CODES, defaults to Bitcoin
        Returns:
            (HDKey)
        '''
        # WIP
        # TODO: get key depending on network
        # data/key, msg, digest
        I = hmac.digest(                                        # noqa: E741
            b'Bitcoin seed',
            root_seed,
            hashlib.sha512)

        # Private key, chain code
        I_left, I_right = I[:32], I[32:]

        root = HDKey(network=network, chain_code=I_right, depth=0, index=0, path='m/')
        root.private_key=I_left
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
        num_mnemonic = HDKey.mnemonic_lookup(value=len(entropy) * 8, value_index=0, lookup_index=2)

        # Formatting to convert hex string to binary string
        bit_format = '0{}b'.format(len(entropy) * 8)

        # Convert hex string to binary string
        bit_string = format(int.from_bytes(entropy, 'big'), bit_format)

        # Append binary string with returned checksum digits
        bit_string += HDKey.checksum(entropy)

        # Number of segments to split bit_string
        segment_len = len(bit_string) // num_mnemonic

        # Split bit_string into segements, each index corresponding to a word
        segments = [int(bit_string[i:i + segment_len]) for i in range(0, len(bit_string), segment_len)]

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
    def convert_to_bytes(key):
        return bytes(secpy256k1.ffi.buffer(key))
