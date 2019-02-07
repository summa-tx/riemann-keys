import unittest
from riemann_keys.hdkey import HDKey, Immutable
from riemann_keys import bip39
from riemann_keys.tests import bip39_test_vectors


class TestImmutable(unittest.TestCase):

    def test_set_attr(self):
        a = Immutable()
        a.attribute = 7
        # NB: double underscore causes name mangling
        #     this is the name mangled immutable variable
        a._Immutable__immutable = True
        with self.assertRaises(TypeError) as context:
            a.attribute = 77
        self.assertIn('cannot be written', str(context.exception))


class TestHDKey(unittest.TestCase):

    def setUp(self):
        self.trezor_vectors = bip39_test_vectors.trezor_vectors
        self.test_vectors = bip39_test_vectors.test_vectors
        self.english_vectors = (self.test_vectors['english']
                                + self.trezor_vectors['english'])

    def test_init_error(self):
        with self.assertRaises(ValueError) as context:
            HDKey({})
        self.assertIn('please instantiate', str(context.exception))

    def test_from_entropy(self):
        for test_vector in self.english_vectors:
            root = HDKey.from_entropy(
                entropy=bytes.fromhex(test_vector['entropy']))
                # salt=test_vector['salt'])
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.xpriv,
                test_vector['derived_node']['xpriv'])
            self.assertEqual(
                node.xpub,
                test_vector['derived_node']['xpub'])
            self.assertEqual(
                node.privkey.hex(),
                test_vector['derived_node']['private_key'])
            self.assertEqual(
                node.pubkey.hex(),
                test_vector['derived_node']['public_key'])
            self.assertEqual(
                node.index,
                test_vector['derived_node']['index'])
            self.assertEqual(
                node.fingerprint,
                bytes.fromhex(test_vector['derived_node']['fingerprint']))
            self.assertEqual(
                node.chain_code,
                bytes.fromhex(test_vector['derived_node']['chain_code']))
            self.assertEqual(
                node.depth, test_vector['derived_node']['depth'])

    def test_from_mnemonic(self):
        for test_vector in self.english_vectors:
            root = HDKey.from_mnemonic(
                mnemonic=test_vector['mnemonic'])
                # salt=test_vector['salt'])
            node = root.derive_path(test_vector['derived_node']['path'])
            print(node.path)
            self.assertEqual(
                node.xpriv,
                test_vector['derived_node']['xpriv'])
            self.assertEqual(
                node.xpub,
                test_vector['derived_node']['xpub'])
            self.assertEqual(
                node.privkey.hex(),
                test_vector['derived_node']['private_key'])
            self.assertEqual(
                node.pubkey.hex(),
                test_vector['derived_node']['public_key'])
            self.assertEqual(
                node.index,
                test_vector['derived_node']['index'])
            self.assertEqual(
                node.fingerprint,
                bytes.fromhex(test_vector['derived_node']['fingerprint']))
            self.assertEqual(
                node.chain_code,
                bytes.fromhex(test_vector['derived_node']['chain_code']))
            self.assertEqual(
                node.depth, test_vector['derived_node']['depth'])

    def test_public_key_generation(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.pubkey.hex(), test_vector['root']['public_key'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.pubkey.hex(), test_vector['root']['public_key'])

    def test_private_key_generation(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.privkey.hex(), test_vector['root']['private_key'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.privkey.hex(), test_vector['root']['private_key'])

    def test_xpub_generation(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.xpub, test_vector['root']['xpub'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.xpub, test_vector['root']['xpub'])

    def test_xpriv_generation(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.xpriv,
                test_vector['root']['xpriv'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.xpriv,
                test_vector['root']['xpriv'])

    def test_fingerprint_generation(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.fingerprint,
                bytes.fromhex(test_vector['root']['fingerprint']))

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.fingerprint,
                bytes.fromhex(test_vector['root']['fingerprint']))

    def test_node_path_derivation(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.xpriv,
                test_vector['derived_node']['xpriv'])
            self.assertEqual(
                node.xpub,
                test_vector['derived_node']['xpub'])
            self.assertEqual(
                node.privkey.hex(),
                test_vector['derived_node']['private_key'])
            self.assertEqual(
                node.pubkey.hex(),
                test_vector['derived_node']['public_key'])
            self.assertEqual(
                node.index,
                test_vector['derived_node']['index'])
            self.assertEqual(
                node.fingerprint,
                bytes.fromhex(test_vector['derived_node']['fingerprint']))
            self.assertEqual(
                node.chain_code,
                bytes.fromhex(test_vector['derived_node']['chain_code']))
            self.assertEqual(
                node.depth, test_vector['derived_node']['depth'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.xpriv,
                test_vector['derived_node']['xpriv'])
            self.assertEqual(
                node.xpub,
                test_vector['derived_node']['xpub'])
            self.assertEqual(
                node.privkey.hex(),
                test_vector['derived_node']['private_key'])
            self.assertEqual(
                node.pubkey.hex(),
                test_vector['derived_node']['public_key'])
            self.assertEqual(
                node.index,
                test_vector['derived_node']['index'])
            self.assertEqual(
                node.fingerprint,
                bytes.fromhex(test_vector['derived_node']['fingerprint']))
            self.assertEqual(
                node.chain_code,
                bytes.fromhex(test_vector['derived_node']['chain_code']))
            self.assertEqual(
                node.depth, test_vector['derived_node']['depth'])

    @unittest.skip('wip')
    def test_node_child_derivation(self):
        ...

    def test_public_keys_when_derived(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.pubkey.hex(),
                test_vector['derived_node']['public_key'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.pubkey.hex(),
                test_vector['derived_node']['public_key'])

    def test_private_keys_when_derived(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.privkey.hex(),
                test_vector['derived_node']['private_key'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.privkey.hex(),
                test_vector['derived_node']['private_key'])

    def test_xpub_when_derived(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.xpub, test_vector['derived_node']['xpub'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.xpub, test_vector['derived_node']['xpub'])

    def test_xpriv_when_derived(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.xpriv,
                test_vector['derived_node']['xpriv'])

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.xpriv,
                test_vector['derived_node']['xpriv'])

    def test_fingerprint_when_derived(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.fingerprint,
                bytes.fromhex(test_vector['derived_node']['fingerprint']))

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.fingerprint,
                bytes.fromhex(test_vector['derived_node']['fingerprint']))
