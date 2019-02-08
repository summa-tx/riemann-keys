import hmac
import hashlib

# import secpy256k1
from secpy256k1 import simple

from riemann_keys import base58, bip39, utils

from typing import cast, List, Optional, Union
from mypy_extensions import TypedDict


KeyDict = TypedDict(
    'KeyDict',
    {
        'path': Optional[str],
        'network': str,
        'depth': Optional[int],
        'parent_fingerprint': Optional[bytes],
        'index': Optional[int],
        'parent': Optional['HDKey'],  # forward type reference
        'chain_code': Optional[bytes],
        'fingerprint': bytes,
        'xpub': Optional[str],
        'xpriv': Optional[str],
        'pubkey': bytes,  # pubkey is always required
        'privkey': Optional[bytes],
    }
)


class Immutable:
    __immutable = False

    def __setattr__(self, key, value):
        if self.__immutable:
            raise TypeError("%r cannot be written to." % self)
        object.__setattr__(self, key, value)

    def _make_immutable(self):
        '''
        Prevents any future changes to the object
        '''
        self.__immutable = True


class HDKey(Immutable):

    path: Optional[str]
    network: str
    depth: Optional[int]
    parent_fingerprint: Optional[bytes]
    index: Optional[int]
    parent: Optional['HDKey']  # forward type reference
    chain_code: Optional[bytes]
    fingerprint: bytes
    xpub: Optional[str]
    xpriv: Optional[str]
    pubkey: bytes  # pubkey is always required
    privkey: Optional[bytes]

    def __init__(self, key_dict: KeyDict, _error_on_call: bool = True,):
        if _error_on_call:
            raise ValueError('please instantiate from a classmethod')
        for k in key_dict:
            setattr(self, k, key_dict[k])  # type: ignore
        self._make_immutable()

    def __repr__(self):  # pragma: nocover
        return '{}{}'.format(
            self.xpub if self.xpub else self.pubkey.hex(),
            ' with privkey' if self.privkey is not None else '')

    def _child_from_xpub(self, index: int, child_xpub: str) -> 'HDKey':
        path: Optional[str]
        if self.path:
            path = '{}/{}'.format(self.path, str(index))
        else:
            path = None
        xpub_bytes = base58.decode(child_xpub)
        pubkey = xpub_bytes[45:78]

        if xpub_bytes[0:4] == utils.VERSION_BYTES['mainnet']['public']:
            network = 'Bitcoin'
        elif xpub_bytes[0:4] == utils.VERSION_BYTES['testnet']['public']:    # pragma: nocover  # noqa: E501
            network = 'Testnet'  # pragma: nocover
        else:
            raise ValueError(
                'unrecognized version bytes.'
                ' Is this an xpub?')  # pragma: nocover

        return HDKey(
            key_dict=KeyDict(
                path=path,
                network=network,
                depth=xpub_bytes[4],
                parent_fingerprint=xpub_bytes[5:9],
                index=int.from_bytes(xpub_bytes[9:13], byteorder='big'),
                parent=self,
                chain_code=xpub_bytes[13:45],
                fingerprint=utils.hash160(pubkey)[:4],
                xpriv=None,
                xpub=child_xpub,
                privkey=None,
                pubkey=pubkey),
            _error_on_call=False)

    def _child_from_xpriv(self, index: int, child_xpriv: str) -> 'HDKey':
        path: Optional[str]
        if self.path:
            if index >= utils.BIP32_HARDEN:
                index_str = '{}h'.format(str(index - utils.BIP32_HARDEN))
            else:
                index_str = str(index)
            path = '{}/{}'.format(self.path, index_str)
        else:
            path = None

        xpriv_bytes = base58.decode(child_xpriv)
        privkey = xpriv_bytes[46:78]
        pubkey = simple.priv_to_pub(privkey)

        if xpriv_bytes[0:4] == utils.VERSION_BYTES['mainnet']['private']:
            network = 'Bitcoin'
        elif xpriv_bytes[0:4] == utils.VERSION_BYTES['testnet']['private']:  # pragma: nocover  # noqa: E501
            network = 'Testnet'  # pragma: nocover
        else:
            raise ValueError(
                'unrecognized version bytes. '
                'Is this an xpriv?')  # pragma: nocover

        return HDKey(
            key_dict=KeyDict(
                path=path,
                network=network,
                depth=xpriv_bytes[4],
                parent_fingerprint=xpriv_bytes[5:9],
                index=index,
                parent=self,
                chain_code=xpriv_bytes[13:45],
                fingerprint=utils.hash160(pubkey)[:4],
                xpriv=child_xpriv,
                xpub=HDKey._xpriv_to_xpub(child_xpriv),
                privkey=privkey,
                pubkey=pubkey),
            _error_on_call=False)

    def _make_child_xpub(
            self,
            child_pubkey: bytes,
            index: int,
            chain_code: bytes) -> str:
        xpub = bytearray()
        xpub.extend(base58.decode(cast(str, self.xpub))[0:4])
        xpub.extend([cast(int, self.depth) + 1])
        xpub.extend(self.fingerprint)
        xpub.extend(index.to_bytes(4, byteorder='big'))
        xpub.extend(chain_code)
        xpub.extend(child_pubkey)
        return base58.encode(xpub)

    def _make_child_xpriv(
            self,
            child_privkey: bytes,
            index: int,
            chain_code: bytes) -> str:
        xpriv = bytearray()
        xpriv.extend(base58.decode(cast(str, self.xpriv))[0:4])
        xpriv.extend([cast(int, self.depth) + 1])
        xpriv.extend(self.fingerprint)
        xpriv.extend(index.to_bytes(4, byteorder='big'))
        xpriv.extend(chain_code)
        xpriv.extend(b'\x00')
        xpriv.extend(child_privkey)
        return base58.encode(xpriv)

    @staticmethod
    def _xpriv_to_xpub(xpriv: str) -> str:
        xpub = bytearray()
        xpriv_bytes = base58.decode(xpriv)

        if xpriv_bytes[0:4] == utils.VERSION_BYTES['mainnet']['private']:
            # mainnet
            xpub.extend(utils.VERSION_BYTES['mainnet']['public'])
        elif xpriv_bytes[0:4] == utils.VERSION_BYTES['testnet']['private']:  # pragma: nocover  # noqa: E501
            # testnet
            xpub.extend(utils.VERSION_BYTES['testnet']['public'])  # pragma: nocover  # noqa: E501
        else:
            raise ValueError(
                'unrecognized version bytes. '
                'Is this an xpub?')  # pragma: nocover

        # verbatim
        xpub.extend(xpriv_bytes[4:45])

        # derive the pubkey
        xpub.extend(simple.priv_to_pub(xpriv_bytes[46:78]))

        return base58.encode(xpub)

    @classmethod
    def from_xpub(HDKey, xpub: str) -> 'HDKey':
        xpub_bytes = base58.decode(xpub)
        pubkey = xpub_bytes[45:78]

        if xpub_bytes[0:4] == utils.VERSION_BYTES['mainnet']['public']:
            network = 'Bitcoin'
        elif xpub_bytes[0:4] == utils.VERSION_BYTES['testnet']['public']:  # pragma: nocover  # noqa: E501
            network = 'Testnet'  # pragma: nocover
        else:
            raise ValueError('unrecognized version bytes. Is this an xpub?')  # pragma: nocover  # noqa: E501

        return HDKey(
            key_dict=KeyDict(
                path=None,
                network=network,
                depth=xpub_bytes[4],
                parent_fingerprint=xpub_bytes[5:9],
                index=int.from_bytes(xpub_bytes[9:13], byteorder='big'),
                parent=None,
                chain_code=xpub_bytes[13:45],
                fingerprint=utils.hash160(pubkey)[:4],
                xpriv=None,
                xpub=xpub,
                privkey=None,
                pubkey=pubkey),
            _error_on_call=False)

    @classmethod
    def from_xpriv(HDKey, xpriv: str) -> 'HDKey':
        xpriv_bytes = base58.decode(xpriv)
        privkey = xpriv_bytes[46:78]
        pubkey = simple.priv_to_pub(privkey)

        if xpriv_bytes[0:4] == utils.VERSION_BYTES['mainnet']['private']:
            network = 'Bitcoin'
        elif xpriv_bytes[0:4] == utils.VERSION_BYTES['testnet']['private']:  # pragma: nocover  # noqa: E501
            network = 'Testnet'  # pragma: nocover
        else:
            raise ValueError('unrecognized version bytes. Is this an xpriv?')  # pragma: nocover  # noqa: E501

        return HDKey(
            key_dict=KeyDict(
                path=None,
                network=network,
                depth=xpriv_bytes[4],
                parent_fingerprint=xpriv_bytes[5:9],
                index=int.from_bytes(xpriv_bytes[9:13], byteorder='big'),
                parent=None,
                chain_code=xpriv_bytes[13:45],
                fingerprint=utils.hash160(pubkey)[:4],
                xpriv=xpriv,
                xpub=HDKey._xpriv_to_xpub(xpriv),
                privkey=privkey,
                pubkey=pubkey),
            _error_on_call=False)

    @classmethod
    def from_pubkey(HDKey, pubkey: bytes, network: str = 'Bitcoin') -> 'HDKey':
        '''
        Instantiates an HDKey from a raw pubkey
        '''
        return HDKey(
            key_dict=KeyDict(
                path=None,
                network=network,
                depth=None,
                parent_fingerprint=None,
                index=None,
                parent=None,
                chain_code=None,
                fingerprint=utils.hash160(pubkey)[:4],
                xpriv=None,
                xpub=None,
                privkey=None,
                pubkey=pubkey),
            _error_on_call=False)

    @classmethod
    def from_privkey(
            HDKey, privkey: bytes, network: str = 'Bitcoin') -> 'HDKey':
        pubkey = simple.priv_to_pub(privkey)
        return HDKey(
            key_dict=KeyDict(
                path=None,
                network=network,
                depth=None,
                parent_fingerprint=None,
                index=None,
                parent=None,
                chain_code=None,
                fingerprint=utils.hash160(pubkey)[:4],
                xpriv=None,
                xpub=None,
                privkey=privkey,
                pubkey=pubkey),
            _error_on_call=False)

    @classmethod
    def from_root_seed(
            HDKey,
            root_seed: bytes,
            network: str = 'Bitcoin') -> 'HDKey':
        '''
        Generates a HDKey object given the root seed.
        Args:
            root_seed (bytes):          128, 256, or 512 bits
            network (str, Optional):    Must be a selection from NETWORK_CODES,
                                        defaults to Bitcoin
        Returns:
            (HDKey)
        '''
        # TODO: get key depending on network
        # data/key, msg, digest
        I = hmac.new(  # noqa: E741
            key=b'Bitcoin seed',
            msg=root_seed,
            digestmod=hashlib.sha512
        ).digest()

        # Private key, chain code
        privkey, chain_code = I[:32], I[32:]
        pubkey = simple.priv_to_pub(privkey)
        print(pubkey)
        xpriv = HDKey._make_master_xpriv(privkey, chain_code, network)
        xpub = HDKey._xpriv_to_xpub(xpriv)
        root = HDKey(
            key_dict=KeyDict(
                path='m',
                network=network,
                depth=0,
                parent_fingerprint=b'\x00' * 4,
                index=0,
                parent=None,
                chain_code=chain_code,
                fingerprint=utils.hash160(pubkey)[:4],
                xpriv=xpriv,
                xpub=xpub,
                privkey=privkey,
                pubkey=pubkey),
            _error_on_call=False)

        return root

    @staticmethod
    def _make_master_xpriv(
            privkey: bytes,
            chain_code: bytes,
            network: str) -> str:
        # TODO: support other networks
        xpriv = bytearray()
        version = utils.VERSION_BYTES['mainnet']['private'] \
            if network == 'Bitcoin' \
            else utils.VERSION_BYTES['testnet']['private']
        xpriv.extend(version)
        xpriv.extend(b'\x00' * 9)  # no depth, no parent, no index
        xpriv.extend(chain_code)
        xpriv.extend(b'\x00')  # padding
        xpriv.extend(privkey)
        return base58.encode(xpriv)

    @classmethod
    def from_entropy(
            HDKey,
            entropy: bytes,
            salt: Optional[str] = None,
            network: str = 'Bitcoin') -> 'HDKey':
        # Lazy
        return HDKey.from_mnemonic(
            mnemonic=bip39.mnemonic_from_entropy(entropy),
            salt=salt,
            network=network)

    @classmethod
    def from_mnemonic(
            HDKey,
            mnemonic: str,
            salt: Optional[str] = None,
            network: str = 'Bitcoin') -> 'HDKey':
        # Lazy
        root_seed = bip39.root_seed_from_mnemonic(mnemonic, salt, network)
        return HDKey.from_root_seed(root_seed, network)

    @staticmethod
    def _parse_derivation(derivation_path: str) -> List[int]:
        '''
        turns a derivation path (e.g. m/44h/0) into a list of integers
        '''
        int_nodes: List[int] = []
        nodes: List[str] = derivation_path.split('/')
        if nodes[0] != 'm':
            raise ValueError('Bad path. Got: {}'.format(derivation_path))
        nodes = nodes[1:]
        for i in range(len(nodes)):
            if nodes[i][-1] in ['h', "'"]:  # Support 0h and 0' conventions
                int_nodes.append(int(nodes[i][:-1]) + utils.BIP32_HARDEN)
            else:
                int_nodes.append(int(nodes[i]))
        return int_nodes

    def derive_path(self, path: str):
        '''
        derives a descendant of the current node
        '''
        if not self.path:
            raise ValueError('current key\'s path is unknown')

        own_path = cast(str, self.path)
        path_nodes = self._parse_derivation(path)
        my_nodes = self._parse_derivation(own_path)

        for i in range(len(my_nodes)):
            if my_nodes[i] != path_nodes[i]:
                raise ValueError('requested child not in descendant branches')

        current_node = self
        for i in range(len(my_nodes), len(path_nodes)):
            current_node = current_node.derive_child(path_nodes[i])
        return current_node

    @staticmethod
    def _normalize_index(idx: Union[int, str]) -> int:
        if type(idx) is int:
            return cast(int, idx)
        str_idx = cast(str, idx)
        if str_idx[-1] in ['h', "'"]:
            return int(str_idx[:-1]) + utils.BIP32_HARDEN
        return int(str_idx)

    def derive_child(self, idx: Union[int, str]):
        '''
        Derives a bip32 child from the current node
        '''
        index: int = self._normalize_index(idx)
        if index >= utils.BIP32_HARDEN and not self.privkey:
            raise ValueError('Need private key to derive hardened children')

        if not self.chain_code:
            raise ValueError('cannot derive child without chain_code')
        else:
            own_chain_code = cast(bytes, self.chain_code)

        index_as_bytes = index.to_bytes(4, byteorder='big')

        data = bytearray()
        if index >= utils.BIP32_HARDEN:
            # Data = 0x00 || ser256(kpar) || ser32(i)
            # (Note: The 0x00 pads the private key to make it 33 bytes long.)
            data.extend(b'\x00')
            data.extend(cast(bytes, self.privkey))
            data.extend(index_as_bytes)
        else:
            # Data = serP(point(kpar)) || ser32(i)).
            data.extend(self.pubkey)
            data.extend(index_as_bytes)

        mac = hmac.new(own_chain_code, digestmod=hashlib.sha512)
        mac.update(data)
        I = mac.digest()  # noqa: E741
        IL, IR = I[:32], I[32:]

        try:
            child_privkey: Optional[bytes]
            if self.privkey:
                child_privkey = simple.tweak_privkey_add(self.privkey, IL)
                child_pubkey = simple.priv_to_pub(child_privkey)
            else:
                child_privkey = None
                child_pubkey = simple.tweak_pubkey_add(self.pubkey, IL)
        except Exception:
            return self.derive_child(index + 1)

        if child_privkey:
            child_xpriv = self._make_child_xpriv(
                cast(bytes, child_privkey), index=index, chain_code=IR)
            return self._child_from_xpriv(index=index, child_xpriv=child_xpriv)
        else:
            child_xpub = self._make_child_xpub(
                child_pubkey, index=index, chain_code=IR)
            return self._child_from_xpub(index=index, child_xpub=child_xpub)

    def sign(self, msg: bytes, hash_func=utils.sha256) -> bytes:
        return simple.sign(self.privkey, msg, hash_func)

    def sign_hash(self, digest: bytes) -> bytes:
        return simple.sign_hash(self.privkey, digest)

    def verify(self, sig: bytes, msg: bytes, hash_func=utils.sha256) -> bool:
        return simple.verify(self.pubkey, sig, msg, hash_func)

    def verify_hash(self, sig: bytes, digest: bytes) -> bool:
        # NB: ECDSA is NOT SECURE unless the verifier calculates the hash
        return simple.verify_hash(self.pubkey, sig, digest)
