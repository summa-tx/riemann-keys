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

    def test_mnemonic_from_entropy(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            self.assertEqual(
                    HDKey.mnemonic_from_entropy(
                        entropy=bytes.fromhex(test_vector['entropy'])),
                    test_vector['mnemonic'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            entropy = bytes.fromhex(test_vector['entropy'])
            self.assertEqual(
                    HDKey.mnemonic_from_entropy(entropy),
                    test_vector['mnemonic'])

        # Test wrong type of entropy.
        with self.assertRaises(ValueError) as context:
            HDKey.mnemonic_from_entropy('fadc2045e8e7daeae18af522ae500143b20ac86f')
        self.assertIn('Entropy must be bytes.', str(context.exception))

        # Test wrong length of entropy.
        with self.assertRaises(ValueError) as context:
            HDKey.mnemonic_from_entropy(entropy=bytes.fromhex('00000000'))
        self.assertIn(
                'Entropy must be 16, 20, 24, 28, or 32 bytes.',
                str(context.exception))

    def test_segments_to_mnemoinc(self):
        # Test Trezor vectors.
        for test_vector in self.test_vectors['english']:
            segments = test_vector['binary'] + test_vector['checksum']
            self.assertEqual(
                HDKey.segments_to_mnemonic(segments=segments.split()),
                test_vector['mnemonic'].split())

            # Test vectors.
        for test_vector in self.test_vectors['english']:
            segments = test_vector['binary'] + test_vector['checksum']
            self.assertEqual(
                HDKey.segments_to_mnemonic(segments=segments.split()),
                test_vector['mnemonic'].split())


    def test_root_seed_from_mnemonic(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            self.assertEqual(
                HDKey.root_seed_from_mnemonic(
                    test_vector['mnemonic'], 'TREZOR').hex(),
                test_vector['seed'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            self.assertEqual(
                HDKey.root_seed_from_mnemonic(test_vector['mnemonic']).hex(),
                test_vector['seed'])

    def test_mnemonic_to_bytes(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            entropy_bytes, checksum = HDKey.mnemonic_to_bytes(
                test_vector['mnemonic'])
            self.assertEqual(entropy_bytes.hex(), test_vector['entropy'])
            self.assertEqual(checksum, test_vector['checksum'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            entropy_bytes, checksum = HDKey.mnemonic_to_bytes(
                test_vector['mnemonic'])
            self.assertEqual(entropy_bytes.hex(), test_vector['entropy'])
            self.assertEqual(checksum, test_vector['checksum'])

    def test_mnemonic_lookup(self):
        with self.assertRaises(ValueError) as context:
            HDKey.mnemonic_lookup('a', 1, 1)
        self.assertIn(
            'Mnemonic lookup value must be of integer type.',
            str(context.exception))

        with self.assertRaises(ValueError) as context:
            HDKey.mnemonic_lookup(1, 'a', 1)
        self.assertIn(
            'Mnemonic value index must be of integer type.',
            str(context.exception))

        with self.assertRaises(ValueError) as context:
            HDKey.mnemonic_lookup(1, 1, 'a')
        self.assertIn(
            'Mnemonic lookup index must be of integer type.',
            str(context.exception))

        # Test checksum
        len_entropy = [128, 160, 192, 224, 256]
        len_checksum = [4, 5, 6, 7, 8]
        for idx, len_e in enumerate(len_entropy):
            self.assertEqual(
                HDKey.mnemonic_lookup(
                    value=len_e,
                    value_index=0,
                    lookup_index=1),
                len_checksum[idx])

    def testimport_word_list(self):
        # Check length of word list.
        self.assertEqual(len(HDKey.import_word_list()), 2048)

    def test_validate_mnemonic(self):
        # Assert False for invalid mnemonics
        self.assertFalse(HDKey.validate_mnemonic(' '.join(['about'] * 12)))
        self.assertFalse(HDKey.validate_mnemonic('hello'))
        self.assertFalse(HDKey.validate_mnemonic(' '.join(['charlie'] * 12)))

        # Assert True for valid mnemonics
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            self.assertTrue(HDKey.validate_mnemonic(test_vector['mnemonic']))

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            self.assertTrue(HDKey.validate_mnemonic(test_vector['mnemonic']))

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
                HDKey.checksum(entropy=entropy),
                test_vector['checksum'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            entropy = bytes.fromhex(test_vector['entropy'])
            self.assertEqual(
                HDKey.checksum(entropy=entropy),
                test_vector['checksum'])
