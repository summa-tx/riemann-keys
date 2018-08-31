import hashlib


class HDKey():

    # NB: (bits of entropy, checksum bits, words in mnemonic)
    MNEMONIC_CODES = (
            (128, 4, 12),
            (160, 5, 15),
            (192, 6, 18),
            (224, 7, 21),
            (256, 8, 24))

    def __init__(self):
        self.network = None
        self.depth = None
        self.index = None
        self.address = None
        self.chain_code = None
        self.private_key = None
        self.public_key = None
        self.fingerprint = None

    @classmethod
    def to_dict(HDKey):
        pass

    @classmethod
    def from_entropy(self, root_seed, salt=b''):
        I = hashlib.pbkdf2_hmac('sha512', root_seed, salt, 2048)  # noqa: E741
        IL, IR = I[32:], I[:32]

        hd_key = HDKey()
        hd_key.private_key = IL
        hd_key.chain_code = IR

        return hd_key

    def derive_descendant(self, derivation_path):
        current = self
        for index in derivation_path.split('/')[1:]:
            current = current.derive_child(index)
        return current

    def derive_child(self, index):
        if 'h' in index:
            pass
        else:
            I = hashlib.pbkdf2_hmac(                            # noqa: E741
                    'sha512', self.chain_code, b'', 2048)
            IL, IR = I[32:], I[:32]

            hd_key = HDKey()
            hd_key.private_key = IL
            hd_key.chain_code = IR
            hd_key.depth = self.depth + 1

            return hd_key

    @staticmethod
    def from_mnemonic(mnemonic, salt=None):
        '''Mnemoinc -> HDKey.
        Generates the 512-bit seed as specified in BIP39 given a mnemonic and
        returns a new HDKey object.
            Args:
                mnemonic    (str): 12, 15, 18, 21, 24 words from word list
                salt        (str): 'mnemonic' + optional words for security
            Returns:
                (HDKey)
        '''
        return HDKey

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
        return HDKey
