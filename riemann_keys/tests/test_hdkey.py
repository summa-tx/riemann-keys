import unittest
from riemann_keys.hdkey import HDKey
from riemann_keys.tests import bip39_test_vectors


class TestHDKey(unittest.TestCase):

    def setUp(self):
        self.trezor_vectors = bip39_test_vectors.trezor_vectors
        self.test_vectors = bip39_test_vectors.test_vectors

    @unittest.skip('wip')
    def test_init(self):
        pass

    @unittest.skip('wip')
    def test_from_entropy(self):
        # Raise ValueError if entropy is not bytes
        with self.assertRaises(ValueError) as context:
            HDKey.from_entropy('000102030405060708090a0b0c0d0e0f')
        self.assertIn('Entropy must be bytes.', str(context.exception))

        # Raise ValueError if entropy byte length is unaccepted
        with self.assertRaises(ValueError) as context:
            HDKey.from_entropy(bytes.fromhex('00000000'))
        self.assertIn(
            'Entropy must be 16, 20, 24, 28, or 32 bytes.',
            str(context.exception))

    @unittest.skip('wip')
    def test_from_root_seed(self):
        pass

    @unittest.skip('wip')
    def test_mnemonic_from_entropy(self):
        #  entropy = bytes.fromhex('a4e3fc4c0161698a22707cfbf30f7f83')
        #  salt = None
        #  mnemonic = 'pilot cable basic actress bird shallow mean auto winner observe that all'   # noqa: E501
        #  seed = 'af44c7ad86ba0a5f46d4c1e785c846db14e0f3d62b69c2ab7efa012a9c9155c024975d6897e36fe9e9e6f0bde55fdf325ff308914ed1b316da0f755f9dd7347d'   # noqa: E501
        #  self.assertIn(HDKey.mnemonic_from_entropy(entropy, salt), mnemonic)
        pass

    @unittest.skip('wip')
    def test_mnemonic_to_bytes(self):
        pass

    @unittest.skip('wip')
    def test_mnemonic_lookup(self):
        pass

    @unittest.skip('wip')
    def test_import_word_list(self):
        pass

    @unittest.skip('wip')
    def test_validate_mnemonic(self):
        pass

    def test_checksum(self):
        # Raise ValueError if entropy is not bytes
        with self.assertRaises(ValueError) as context:
            HDKey.from_entropy('000102030405060708090a0b0c0d0e0f')
        self.assertIn('Entropy must be bytes.', str(context.exception))

        # Raise ValueError if entropy byte length is unaccepted
        with self.assertRaises(ValueError) as context:
            HDKey.from_entropy(bytes.fromhex('00000000'))
        self.assertIn(
            'Entropy must be 16, 20, 24, 28, or 32 bytes.',
            str(context.exception))

        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            entropy = bytes.fromhex(test_vector['entropy'])
            self.assertEqual(
                HDKey._checksum(entropy=entropy),
                test_vector['checksum'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            entropy = bytes.fromhex(test_vector['entropy'])
            self.assertEqual(
                HDKey._checksum(entropy=entropy),
                test_vector['checksum'])
