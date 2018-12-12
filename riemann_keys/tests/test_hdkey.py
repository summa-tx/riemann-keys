import unittest
from riemann_keys.hdkey import HDKey
from riemann_keys.tests import bip39_test_vectors
from ptpdb import set_trace


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
    def test_from_mnemonic(self):
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
            HDKey.mnemonic_from_entropy(
                'fadc2045e8e7daeae18af522ae500143b20ac86f')
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

    def test_public_key_generation(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(root.public_key.hex(), test_vector['root']['public_key'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(root.public_key.hex(), test_vector['root']['public_key'])

    def test_public_key_setting(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            node = HDKey()
            node.private_key = test_vector['root']['public_key']
            self.assertEqual(node.public_key.hex(), test_vector['root']['public_key'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            node = HDKey()
            node.private_key = test_vector['root']['public_key']
            self.assertEqual(node.public_key.hex(), test_vector['root']['public_key'])

    def test_private_key_generation(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(root.private_key.hex(), test_vector['root']['private_key'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(root.private_key.hex(), test_vector['root']['private_key'])

    def test_private_key_setting(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            node = HDKey()
            node.private_key = test_vector['root']['private_key']
            self.assertEqual(node.private_key.hex(), test_vector['root']['private_key'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            node = HDKey()
            node.private_key = test_vector['root']['private_key']
            self.assertEqual(node.private_key.hex(), test_vector['root']['private_key'])

    def test_xpub_generation(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(root.extended_public_key, test_vector['root']['xpub'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(root.extended_public_key, test_vector['root']['xpub'])

    def test_xpub_setting(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            node = HDKey()
            node.extended_public_key = test_vector['root']['xpub']
            self.assertEqual(
                node.extended_public_key, test_vector['root']['xpub'])
            self.assertEqual(
                node.public_key.hex(), test_vector['root']['public_key'])
            self.assertEqual(
                node.index, test_vector['root']['index'])
            self.assertEqual(
                node.fingerprint, test_vector['root']['fingerprint'])
            self.assertEqual(
                node.chain_code, test_vector['root']['chaincode'])
            self.assertEqual(node.depth, test_vector['root']['depth'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            node = HDKey()
            node.extended_public_key = test_vector['root']['xpub']
            self.assertEqual(
                node.extended_public_key, test_vector['root']['xpub'])
            self.assertEqual(
                node.public_key.hex(), test_vector['root']['public_key'])
            self.assertEqual(
                node.index, test_vector['root']['index'])
            self.assertEqual(
                node.fingerprint, test_vector['root']['fingerprint'])
            self.assertEqual(
                node.chain_code, test_vector['root']['chaincode'])
            self.assertEqual(node.depth, test_vector['root']['depth'])

    def test_xpriv_generation(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.extended_private_key, test_vector['root']['xpriv'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.extended_private_key, test_vector['root']['xpriv'])

    def test_xpriv_setting(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            node = HDKey()
            node.extended_private_key = test_vector['root']['xpriv']
            self.assertEqual(
                node.extended_private_key, test_vector['root']['xpriv'])
            self.assertEqual(
                node.private_key.hex(), test_vector['root']['private_key'])
            self.assertEqual(
                node.index, test_vector['root']['index'])
            self.assertEqual(
                node.fingerprint, test_vector['root']['fingerprint'])
            self.assertEqual(
                node.chain_code, test_vector['root']['chaincode'])
            self.assertEqual(node.depth, test_vector['root']['depth'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            node = HDKey()
            node.extended_private_key = test_vector['root']['xpriv']
            self.assertEqual(
                node.extended_private_key, test_vector['root']['xpriv'])
            self.assertEqual(
                node.private_key.hex(), test_vector['root']['private_key'])
            self.assertEqual(
                node.index, test_vector['root']['index'])
            self.assertEqual(
                node.fingerprint, test_vector['root']['fingerprint'])
            self.assertEqual(
                node.chain_code, test_vector['root']['chaincode'])
            self.assertEqual(node.depth, test_vector['root']['depth'])

    def test_fingerprint_generation(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.fingerprint, test_vector['root']['fingerprint'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.fingerprint, test_vector['root']['fingerprint'])

    def test_fingerprint_setting(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            node = HDKey()
            node.fingerprint = test_vector['root']['fingerprint']
            self.assertEqual(
                node.fingerprint, test_vector['root']['fingerprint'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            node = HDKey()
            node.fingerprint = test_vector['root']['fingerprint']
            self.assertEqual(
                node.fingerprint, test_vector['root']['fingerprint'])

    def test_node_path_derivation(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.extended_private_key, 
                test_vector['derived_node']['xpriv'])
            self.assertEqual(
                node.extended_public_key, 
                test_vector['derived_node']['xpub'])
            self.assertEqual(
                node.private_key.hex(), 
                test_vector['derived_node']['private_key'])
            self.assertEqual(
                node.public_key.hex(), test_vector['derived_node']['public_key'])
            self.assertEqual(
                node.index, test_vector['derived_node']['index'])
            self.assertEqual(
                node.fingerprint, 
                test_vector['derived_node']['fingerprint'])
            self.assertEqual(
                node.chain_code, test_vector['derived_node']['chaincode'])
            self.assertEqual(
                node.depth, test_vector['derived_node']['depth'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.extended_private_key, 
                test_vector['derived_node']['xpriv'])
            self.assertEqual(
                node.extended_public_key, 
                test_vector['derived_node']['xpub'])
            self.assertEqual(
                node.private_key.hex(), 
                test_vector['derived_node']['private_key'])
            self.assertEqual(
                node.public_key.hex(), test_vector['derived_node']['public_key'])
            self.assertEqual(
                node.index, test_vector['derived_node']['index'])
            self.assertEqual(
                node.fingerprint, 
                test_vector['derived_node']['fingerprint'])
            self.assertEqual(
                node.chain_code, test_vector['derived_node']['chaincode'])
            self.assertEqual(
                node.depth, test_vector['derived_node']['depth'])

    @unittest.skip('wip')
    def test_node_child_derivation(self):
        pass

    def test_public_keys_when_derived(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.public_key.hex(), test_vector['derived_node']['public_key'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.public_key.hex(), test_vector['derived_node']['public_key'])

    def test_private_keys_when_derived(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.public_key.hex(), test_vector['derived_node']['private_key'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.public_key.hex(), test_vector['derived_node']['private_key'])

    def test_xpub_when_derived(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.public_key.hex(), test_vector['derived_node']['xpub'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.public_key.hex(), test_vector['derived_node']['xpub'])

    def test_xpriv_when_derived(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.public_key.hex(), test_vector['derived_node']['xpriv'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.public_key.hex(), test_vector['derived_node']['xrpiv'])

    def test_fingerprint_when_derived(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.public_key.hex(), test_vector['derived_node']['fingerprint'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = HDKey.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.public_key.hex(), test_vector['derived_node']['fingerprint'])

    @unittest.skip('wip')
    def test_convert_to_bytes(self):
        pass

    @unittest.skip('wip')
    def test_hash160(self):
        pass
