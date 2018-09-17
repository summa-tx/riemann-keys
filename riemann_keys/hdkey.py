import pkg_resources
import hmac
from riemann_keys import utils


class HDKey:

    # NB: (bits of entropy, checksum bits, words in mnemonic)
    MNEMONIC_CODES = (
        (128, 4, 12),
        (160, 5, 15),
        (192, 6, 18),
        (224, 7, 21),
        (256, 8, 24),
    )

    def __init__(self, depth, index, path, network, parent, chain_code=None):
        # WIP
        self.path = path
        self.depth = depth
        self.index = index
        self.network = network if network is not None else "Bitcoin"
        self.chain_code = chain_code
        self.private_key = None
        self.public_key = None
        self.parent = parent

    def derive_path(self, path):  # m/44/1/1/1/1
        if len(path) == 0:
            return self

        path = path.split("/")  # ['m', '44', '1', '1', '1', '1']
        current_node = path.pop(0)  # pop the first index

        if (
            current_node.lower() == "m"
            or current_node.lower() == "m'"
            and len(path) == 1
        ):
            # total path is ['m']
            return self  # total path is ['m']
        elif current_node.lower() == "m" or current_node.lower() == "m'":
            return self.derive_path(path)

        hardened = False
        # if we're here, then we have a path that doesn't start with m
        if "'" in current_node:
            current_node = int(current_node[:-1]) + 0x80000000  # 0x80000000 == 2^31,
            hardened = True

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
        root_seed = HDKey.root_from_mnemonic(mnemonic, network)

        # Generate master keys and chain code from root_seed
        return HDKey.from_root_seed(root_seed, network)

    @staticmethod
    def from_root_seed(root_seed, network='Bitcoin'):
        '''
        Generates a HDKey object given the root seed.
        Args:
            root_seed (bytes): 128, 256, or 512 bits
        Returns:
            (HDKey)
        '''
        # WIP
        # TODO: get key depending on network
        I = utils.hmac_sha512(key=b'Bitcoin seed', msg=root_seed)  # noqa: E741

        # Private key, chain code
        I_left, I_right = I[:32], I[32:]

        # TODO: get path depending on network
        path = 'm/0'  # temp

        return HDKey(
                network=network,
                private_key=I_left,
                chain_code=I_right,
                depth=0,
                index=0,
                path=path)

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
            lookup_index=2)

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
            for i in range(0, len(bit_string), segment_len)]

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
        Generates the 512-bit seed as specified in BIP39 given a mnemonic and
        returns a new HDKey object.
        Args:
            mnemonic    (str): 12, 15, 18, 21, 24 words from word list
            salt        (str): optional words for added security
        Returns:
            (HDKey)
        '''
        HDKey.validate_mnemonic(mnemonic)
        salt = 'mnemonic' + (salt if salt is not None else '')
        salt_bytes = salt.encode('utf-8')
        mnemonic_bytes = mnemonic.encode('utf-8')
        return utils.pbkdf2_hmac(data=mnemonic_bytes, salt=salt_bytes)

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
            utils.sha256(entropy), 'big'), '0256b')[:checksum_len]

    @staticmethod
    def validate_entropy(entropy):
        if not isinstance(entropy, bytes):
            raise ValueError('Entropy must be bytes.')

        len_e = len(entropy)
        if len_e not in list(map(lambda x: x // 8, [128, 160, 192, 224, 256])):
            raise ValueError('Entropy must be 16, 20, 24, 28, or 32 bytes.')

        return True
