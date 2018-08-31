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
        # get mnemonic -> check right number of words, words exist in list
        # handle salt -> check it starts with 'mnemonic'
        # get 512 bit seed by key stretching (pbkdf2 using HMAC-SHA512 for 2048 rounds)
        # return call from_entropy with 512 bit seed
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
