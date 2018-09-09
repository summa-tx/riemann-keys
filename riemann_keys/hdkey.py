import hashlib


class HDKey():
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
        I = hashlib.pbkdf2_hmac('sha512', root_seed, salt, 2048)
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
            I = hashlib.pbkdf2_hmac('sha512', self.chain_code, b'', 2048)
            IL, IR = I[32:], I[:32]

            hd_key = HDKey()
            hd_key.private_key = IL
            hd_key.chain_code = IR
            hd_key.depth = self.depth + 1

            return hd_key
