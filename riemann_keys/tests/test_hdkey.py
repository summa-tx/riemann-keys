import unittest
from unittest import mock

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

    # def assertEqual(self, *args):
    #     print(*args)
    #     assert args[0] == args[1]

    def setUp(self):
        self.trezor_vectors = bip39_test_vectors.trezor_vectors
        self.test_vectors = bip39_test_vectors.test_vectors
        self.english_vectors = (self.test_vectors['english']
                                + self.trezor_vectors['english'])
        self.public_path = bip39_test_vectors.public_path

    def test_init_error(self):
        with self.assertRaises(ValueError) as context:
            HDKey({})
        self.assertIn('please instantiate', str(context.exception))

    def test_from_root_seed(self):
        for test_vector in self.english_vectors:
            root = HDKey.from_root_seed(bytes.fromhex(test_vector['seed']))
            child = root.derive_path(test_vector['derived_node']['path'])
            for (obj, choice) in zip([root, child], ['root', 'derived_node']):
                self.assertEqual(
                    obj.xpriv,
                    test_vector[choice]['xpriv'])
                self.assertEqual(
                    obj.xpub,
                    test_vector[choice]['xpub'])
                self.assertEqual(
                    obj.privkey.hex(),
                    test_vector[choice]['private_key'])
                self.assertEqual(
                    obj.pubkey.hex(),
                    test_vector[choice]['public_key'])
                self.assertEqual(
                    obj.index,
                    test_vector[choice]['index'])
                self.assertEqual(
                    obj.fingerprint,
                    bytes.fromhex(test_vector[choice]['fingerprint']))
                self.assertEqual(
                    obj.chain_code,
                    bytes.fromhex(test_vector[choice]['chain_code']))
                self.assertEqual(
                    obj.depth, test_vector[choice]['depth'])

    def test_from_entropy(self):
        for test_vector in self.english_vectors:
            root = HDKey.from_entropy(
                entropy=bytes.fromhex(test_vector['entropy']),
                salt=test_vector['salt'])
            child = root.derive_path(test_vector['derived_node']['path'])
            for (obj, choice) in zip([root, child], ['root', 'derived_node']):
                self.assertEqual(
                    obj.xpriv,
                    test_vector[choice]['xpriv'])
                self.assertEqual(
                    obj.xpub,
                    test_vector[choice]['xpub'])
                self.assertEqual(
                    obj.privkey.hex(),
                    test_vector[choice]['private_key'])
                self.assertEqual(
                    obj.pubkey.hex(),
                    test_vector[choice]['public_key'])
                self.assertEqual(
                    obj.index,
                    test_vector[choice]['index'])
                self.assertEqual(
                    obj.fingerprint,
                    bytes.fromhex(test_vector[choice]['fingerprint']))
                self.assertEqual(
                    obj.chain_code,
                    bytes.fromhex(test_vector[choice]['chain_code']))
                self.assertEqual(
                    obj.depth, test_vector[choice]['depth'])

    def test_from_mnemonic(self):
        for test_vector in self.english_vectors:
            root = HDKey.from_mnemonic(
                mnemonic=test_vector['mnemonic'],
                salt=test_vector['salt'])
            child = root.derive_path(test_vector['derived_node']['path'])
            for (obj, choice) in zip([root, child], ['root', 'derived_node']):
                self.assertEqual(
                    obj.xpriv,
                    test_vector[choice]['xpriv'])
                self.assertEqual(
                    obj.xpub,
                    test_vector[choice]['xpub'])
                self.assertEqual(
                    obj.privkey.hex(),
                    test_vector[choice]['private_key'])
                self.assertEqual(
                    obj.pubkey.hex(),
                    test_vector[choice]['public_key'])
                self.assertEqual(
                    obj.index,
                    test_vector[choice]['index'])
                self.assertEqual(
                    obj.fingerprint,
                    bytes.fromhex(test_vector[choice]['fingerprint']))
                self.assertEqual(
                    obj.chain_code,
                    bytes.fromhex(test_vector[choice]['chain_code']))
                self.assertEqual(
                    obj.depth, test_vector[choice]['depth'])

    def test_public_key_generation(self):
        # Test vectors.
        for test_vector in self.english_vectors:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'],
                salt=test_vector['salt'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.pubkey.hex(), test_vector['root']['public_key'])

    def test_private_key_generation(self):
        # Test vectors.
        for test_vector in self.english_vectors:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'],
                salt=test_vector['salt'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.privkey.hex(), test_vector['root']['private_key'])

    def test_xpub_generation(self):
        # Test vectors.
        for test_vector in self.english_vectors:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'],
                salt=test_vector['salt'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.xpub, test_vector['root']['xpub'])

    def test_xpriv_generation(self):
        # Test vectors.
        for test_vector in self.english_vectors:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'],
                salt=test_vector['salt'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.xpriv,
                test_vector['root']['xpriv'])

    def test_fingerprint_generation(self):
        # Test vectors.
        for test_vector in self.english_vectors:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'],
                salt=test_vector['salt'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            self.assertEqual(
                root.fingerprint,
                bytes.fromhex(test_vector['root']['fingerprint']))

    def test_node_path_derivation(self):
        # Test vectors.
        for test_vector in self.english_vectors:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'],
                salt=test_vector['salt'])
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

    def test_public_keys_when_derived(self):
        # Test vectors.
        for test_vector in self.english_vectors:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'],
                salt=test_vector['salt'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.pubkey.hex(),
                test_vector['derived_node']['public_key'])

    def test_private_keys_when_derived(self):
        # Test vectors.
        for test_vector in self.english_vectors:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'],
                salt=test_vector['salt'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.privkey.hex(),
                test_vector['derived_node']['private_key'])

    def test_xpub_when_derived(self):
        # Test vectors.
        for test_vector in self.english_vectors:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'],
                salt=test_vector['salt'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.xpub, test_vector['derived_node']['xpub'])

    def test_xpriv_when_derived(self):
        # Test vectors.
        for test_vector in self.english_vectors:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'],
                salt=test_vector['salt'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.xpriv,
                test_vector['derived_node']['xpriv'])

    def test_fingerprint_when_derived(self):
        # Test vectors.
        for test_vector in self.english_vectors:
            root_seed = bip39.root_seed_from_mnemonic(
                mnemonic=test_vector['mnemonic'],
                salt=test_vector['salt'])
            root = HDKey.from_root_seed(
                root_seed=root_seed)
            node = root.derive_path(test_vector['derived_node']['path'])
            self.assertEqual(
                node.fingerprint,
                bytes.fromhex(test_vector['derived_node']['fingerprint']))

    def test_public_derivation(self):
        node = HDKey.from_xpub(self.public_path[0])
        child = node.derive_child(0)
        grandchild = child.derive_child(0)
        self.assertEqual(
            child.xpub,
            self.public_path[1])
        self.assertEqual(
            grandchild.xpub,
            self.public_path[2])

    def test_public_derivation_with_path(self):
        node = HDKey.from_mnemonic(bip39_test_vectors.public_path_mnemonic)
        child = node.derive_child(0)
        grandchild = child.derive_child(0)
        self.assertEqual(
            child.xpub,
            self.public_path[1])
        self.assertEqual(
            grandchild.xpub,
            self.public_path[2])
        self.assertEqual(grandchild.path, 'm/0/0')

    def test_child_from_xpub(self):
        node = HDKey.from_mnemonic(bip39_test_vectors.public_path_mnemonic)
        child = node._child_from_xpub(0, self.public_path[1])
        self.assertEqual(child.path, 'm/0')

    def test_child_from_xpriv(self):
        node = HDKey.from_xpriv(
            self.english_vectors[4]['root']['xpriv'])
        child = node.derive_child("51h")
        self.assertEqual(
            child.xpriv,
            self.english_vectors[4]['derived_node']['xpriv'])

    def test_from_pubkey(self):
        pk = bytes.fromhex('02800f0237e39dce74f506c508985d4d71f8020342d7dfe781ca5cfb73e63eb43e')  # noqa: E501
        node = HDKey.from_pubkey(pk)
        self.assertEqual(node.pubkey, pk)

    def test_parse_derivation_error(self):
        with self.assertRaises(ValueError) as context:
            HDKey._parse_derivation('44')
        self.assertIn('Bad path. ', str(context.exception))

    def test_derive_path_unknown(self):
        node = HDKey.from_privkey(b'\x32' * 32)
        with self.assertRaises(ValueError) as context:
            node.derive_path('6')
        self.assertIn('path is unknown', str(context.exception))

    def test_derive_path_not_descendent(self):
        root = HDKey.from_mnemonic(bip39_test_vectors.public_path_mnemonic)
        child = root.derive_path('m/0/0')
        with self.assertRaises(ValueError) as context:
            child.derive_path('m/1/1')
        self.assertIn('requested child not in', str(context.exception))

    def test_normalize_index(self):
        self.assertEqual(
            HDKey._normalize_index(7),
            7)
        self.assertEqual(
            HDKey._normalize_index('7'),
            7)
        self.assertEqual(
            HDKey._normalize_index('7h'),
            7 + 0x80000000)
        self.assertEqual(
            HDKey._normalize_index("7'"),
            7 + 0x80000000)

    def test_derive_child_hardened_no_privkey(self):
        pk = bytes.fromhex('02800f0237e39dce74f506c508985d4d71f8020342d7dfe781ca5cfb73e63eb43e')  # noqa: E501
        node = HDKey.from_pubkey(pk)
        with self.assertRaises(ValueError) as context:
            node.derive_child('1h')
        self.assertIn('Need private key', str(context.exception))

    def test_derive_child_hardened_no_chaincode(self):
        sk = b'\x32' * 32
        node = HDKey.from_privkey(sk)
        with self.assertRaises(ValueError) as context:
            node.derive_child('1h')
        self.assertIn('without chain_code', str(context.exception))

    @mock.patch('riemann_keys.hdkey.simple.tweak_privkey_add')
    def test_derive_child_invalid_result(self, mock_tweak):
        mock_tweak.side_effect = [
            b'\xff' * 32, b'\x33' * 32]

        node = HDKey.from_mnemonic(bip39_test_vectors.public_path_mnemonic)
        child = node.derive_child(0)
        self.assertEqual(child.path, 'm/1')

    def test_sign_errors(self):
        pk = bytes.fromhex('02800f0237e39dce74f506c508985d4d71f8020342d7dfe781ca5cfb73e63eb43e')  # noqa: E501
        node = HDKey.from_pubkey(pk)

        with self.assertRaises(ValueError) as context:
            node.sign(b'\x00')
        self.assertIn('without privkey', str(context.exception))

        with self.assertRaises(ValueError) as context:
            node.sign_hash(b'\x00' * 32)
        self.assertIn('without privkey', str(context.exception))
