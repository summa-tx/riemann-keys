import unittest
from riemann_keys.hdkey import HDKey
from riemann_keys import bip39
from riemann_keys.tests import bip39_test_vectors


class TestHDKey(unittest.TestCase):

    def setUp(self):
        self.trezor_vectors = bip39_test_vectors.trezor_vectors
        self.test_vectors = bip39_test_vectors.test_vectors

    @unittest.skip('wip')
    def test_init(self):
        ...

    @unittest.skip('wip')
    def test_from_entropy(self):
        ...

    @unittest.skip('wip')
    def test_from_root_seed(self):
        ...

    @unittest.skip('wip')
    def test_from_mnemonic(self):
        ...

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
                root.xpub, bytes(test_vector['root']['xpub'], 'utf8'))

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.xpub, bytes(test_vector['root']['xpub'], 'utf8'))

    def test_xpriv_generation(self):
        # Test Trezor vectors.
        for test_vector in self.trezor_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.xpriv,
                bytes(test_vector['root']['xpriv'], 'utf8'))

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.xpriv,
                bytes(test_vector['root']['xpriv'], 'utf8'))

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
                bytes(test_vector['derived_node']['xpriv'], 'utf8')),
            self.assertEqual(
                node.xpub,
                bytes(test_vector['derived_node']['xpub'], 'utf8'))
            self.assertEqual(
                node.privkey.hex(),
                test_vector['derived_node']['private_key'])
            self.assertEqual(
                node.pubkey.hex(),
                test_vector['derived_node']['public_key'])
            self.assertEqual(
                node.index,
                int(test_vector['derived_node']['index']).to_bytes(4, "big"))
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
                bytes(test_vector['derived_node']['xpriv'], 'utf8')),
            self.assertEqual(
                node.xpub,
                bytes(test_vector['derived_node']['xpub'], 'utf8')),
            self.assertEqual(
                node.privkey.hex(),
                test_vector['derived_node']['private_key'])
            self.assertEqual(
                node.pubkey.hex(),
                test_vector['derived_node']['public_key'])
            self.assertEqual(
                node.index,
                int(test_vector['derived_node']['index']).to_bytes(4, "big"))
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
                node.xpub, bytes(test_vector['derived_node']['xpub'], 'utf8'))

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.xpub, bytes(test_vector['derived_node']['xpub'], 'utf8'))

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
                bytes(test_vector['derived_node']['xpriv'], "utf8"))

        # Test vectors.
        for test_vector in self.test_vectors['english']:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.xpriv,
                bytes(test_vector['derived_node']['xpriv'], "utf8"))

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
