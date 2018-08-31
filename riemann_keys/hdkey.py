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
        salt = 'mnemonic' + (salt if salt is not None else '')
        salt_bytes = salt.encode('utf-8')
        mnemonic_bytes = mnemonic.encode('utf-8')
        return HDKey.from_entropy(utils.pbkdf2_hmac(
                data=mnemonic_bytes,
                salt=salt_bytes))

    @staticmethod
    def from_generated_mnemonic(num_words=24):
        '''Mnemoinc -> HDKey.
        Given the mnemonic word length, generates the 512-bit seed as
        specified in BIP39 from a mnemonic generated with entropy via
        os.urandom and returns a new HDKey object.
            Args:
                num_words   (int): mnemonic word length: 12, 15, 18, 21, 24
            Returns:
                (HDKey)
        '''
        pass
