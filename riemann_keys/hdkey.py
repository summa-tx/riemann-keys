import pkg_resources
from riemann_keys import utils


class HDKey():

    # NB: (bits of entropy, checksum bits, words in mnemonic)
    MNEMONIC_CODES = (
            (128, 4, 12),
            (160, 5, 15),
            (192, 6, 18),
            (224, 7, 21),
            (256, 8, 24))

    def __init__(self, private_key, chain_code, depth, index, path, network):
        self.path = path
        self.depth = depth
        self.index = index
        self.network = (network if network is not None else 'Bitcoin')
        self.chain_code = chain_code

        self.address = None
        self.private_key = None
        self.public_key = None

    @staticmethod
    def from_entropy(entropy, network='Bitcoin'):
        '''
        Args:
            entropy (bytes): 128-512 bits
        '''
        # TODO: check entropy validity
        # TODO: get key depending on network
        I = utils.hmac_sha512(key=b'Bitcoin seed', msg=entropy)    # noqa: E741

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
    def from_mnemonic(mnemonic, salt=None, network='Bitcoin'):
        '''Mnemoinc -> HDKey.
        Generates the 512-bit seed as specified in BIP39 given a mnemonic and
        returns a new HDKey object.
        Args:
            mnemonic    (str): 12, 15, 18, 21, 24 words from word list
            salt        (str): optional words for added security
        Returns:
            (HDKey)
        '''
        HDKey._validate_mnemonic(mnemonic)
        salt = 'mnemonic' + (salt if salt is not None else '')
        salt_bytes = salt.encode('utf-8')
        mnemonic_bytes = mnemonic.encode('utf-8')
        return HDKey.from_entropy(utils.pbkdf2_hmac(
                data=mnemonic_bytes,
                salt=salt_bytes))

    @staticmethod
    def _mnemonic_to_bytes(mnemonic):
        '''Mnemonic -> [bytes]
        Args:
            mnemonic    (str): a 12, 15, 18, 21, or 24 word str
        Returns:
            (bytes): the entropy bytes
              (str): the checksum bits as an bitstring
        '''
        words = mnemonic.split()
        word_list = HDKey._import_word_list()
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
        checksum_bits = HDKey._mnemonic_lookup(
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
    def _mnemonic_lookup(value, value_index, lookup_index):
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
    def _import_word_list():
        '''Imports BIP39 word list.
        Returns:
            (list): 2048 words specified in BIP39
        '''
        words = []

        # Import mnemonic words
        word_list = pkg_resources.resource_string(
            'riemann_keys.data', 'english.txt').decode('utf-8')

        # Create mnemonic word list
        for word in word_list.split('\n')[:-1]:
            words.append(word)

        return words

    @staticmethod
    def _validate_mnemonic(mnemonic):
        '''Validates a mnemonic
        Args:
            mnemonic    (string): potential mnemonic string
        Returns:
            (bool): true if the string is a valid mnemonic, otherwise false
        '''
        # Check the length
        mnem_lens = [c[2] for c in HDKey.MNEMONIC_CODES]
        split = mnemonic.split()
        words = HDKey._import_word_list()
        if len(split) not in mnem_lens:
            return False

        # Check each word against the list
        for word in split:
            if word not in words:
                return False

        # Check the checksum
        entropy_bytes, checksum = HDKey._mnemonic_to_bytes(mnemonic)
        if HDKey._checksum(entropy_bytes) != checksum:
            return False

        return True
