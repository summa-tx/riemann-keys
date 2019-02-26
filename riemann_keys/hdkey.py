import hmac
import hashlib
import warnings

from secpy256k1 import simple

from riemann_keys import base58, bip39, utils

from typing import Any, cast, Callable, List, Optional, Union
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

    def __setattr__(self, key: str, value: Any) -> None:
        '''
        __setattr__ function controls behavior on attr assignment
        we override it to prevent any property from being changed
        In order for this to work, all property types must be immutable
        So use Tuples instead of List, and avoid dictionaries
        Args:
            key   (str): the property name
            value (Any): what we should set the property to
        '''
        if self.__immutable:
            raise TypeError('This object cannot be written to.')
        object.__setattr__(self, key, value)

    def _make_immutable(self) -> None:
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
        '''
        instantiate an HDKey
        We want users to call the classmethods to instantiate, so we make this
            error if they don't pass an additional argument. Users can override
            but by default bare instantiation is disabled.
        Args:
            key_dict       (dict): the key information for the new object
            _error_on_call (bool): if true, causes this call to error

        '''
        if _error_on_call:
            raise ValueError('please instantiate from a classmethod')
        for k in key_dict:
            setattr(self, k, key_dict[k])  # type: ignore
        self._make_immutable()

    def __repr__(self):  # pragma: nocover
        '''
        ___repr__ is called to make a string representation of the object. In
            this case it's the xpub or pubkey with an indicator of whether we
            have the privkey
        Returns:
            str: the representation
        '''
        return '{}{}'.format(
            self.xpub if self.xpub else self.pubkey.hex(),
            ' with privkey' if self.privkey is not None else '')

    def _child_from_xpub(self, index: int, child_xpub: str) -> 'HDKey':
        '''
        Returns a new HDKey object based on the current object and the new
            child xpub. Don't call this directly, it's for child derivation.
        Args:
            index      (int): the index of the child
            child_xpub (str): the child's xpub
        Returns
            HDKey: the new child object
        '''
        path: Optional[str]
        if self.path is not None:
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
        '''
        Returns a new HDKey object based on the current object and the new
            child xpriv. Don't call this directly, it's for child derivation.
        Args:
            index       (int): the index of the child
            child_xpriv (str): the child's xpriv
        Returns
            HDKey: the new child object
        '''
        # set the path, if this key has a path
        path: Optional[str]
        if self.path is not None:
            if index >= utils.BIP32_HARDEN:
                index_str = '{}h'.format(str(index - utils.BIP32_HARDEN))
            else:
                index_str = str(index)
            path = '{}/{}'.format(self.path, index_str)
        else:
            path = None

        # Make the pubkey
        xpriv_bytes = base58.decode(child_xpriv)
        privkey = xpriv_bytes[46:78]
        pubkey = simple.priv_to_pub(privkey)

        # What network is this for?
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
        '''
        Makes a child xpub based on the current key and the child key info.
        Args:
            child_pubkey (bytes): the child pubkey
            index          (int): the child index
            chain_code   (bytes): the child chain code
        Returns
            (str): the child xpub
        '''
        xpub = bytearray()
        xpub.extend(base58.decode(cast(str, self.xpub))[0:4])  # prefix
        xpub.extend([cast(int, self.depth) + 1])               # depth
        xpub.extend(self.fingerprint)                          # fingerprint
        xpub.extend(index.to_bytes(4, byteorder='big'))        # index
        xpub.extend(chain_code)                                # chain_code
        xpub.extend(child_pubkey)                              # pubkey (comp)
        return base58.encode(xpub)

    def _make_child_xpriv(
            self,
            child_privkey: bytes,
            index: int,
            chain_code: bytes) -> str:
        '''
        Makes a child xpriv based on the current key and the child key info.
        Args:
            child_privkey (bytes): the child privkey
            index           (int): the child index
            chain_code    (bytes): the child chain code
        Returns
            (str): the child xpriv
        '''
        xpriv = bytearray()
        xpriv.extend(base58.decode(cast(str, self.xpriv))[0:4])  # prefix
        xpriv.extend([cast(int, self.depth) + 1])                # depth
        xpriv.extend(self.fingerprint)                           # fingerprint
        xpriv.extend(index.to_bytes(4, byteorder='big'))         # index
        xpriv.extend(chain_code)                                 # chain_code
        xpriv.extend(b'\x00')                                    # priv padding
        xpriv.extend(child_privkey)                              # privkey
        return base58.encode(xpriv)

    @staticmethod
    def _xpriv_to_xpub(xpriv: str) -> str:
        '''
        Turns an xpriv into an xpub.
        Args:
            xpriv (str): the b58 encoded xpriv
        Returns:
        '''
        xpub = bytearray()
        xpriv_bytes = base58.decode(xpriv)

        # determine what network the key is on
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

        # most parts are verbatim
        xpub.extend(xpriv_bytes[4:45])

        # derive the pubkey and append it
        xpub.extend(simple.priv_to_pub(xpriv_bytes[46:78]))

        return base58.encode(xpub)

    @classmethod
    def from_xpub(HDKey, xpub: str, path: Optional[str] = None) -> 'HDKey':
        '''
        Instantiate an HDKey from an xpub. Populates all possible fields
        Args:
            xpub (str): the xpub
            path (str): the path if it's known. useful for calling derive_path
        Returns:
            (HDKey): the key object
        '''
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
                path=path,
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
    def from_xpriv(HDKey, xpriv: str, path: Optional[str] = None) -> 'HDKey':
        '''
        Instantiate an HDKey from an xpriv. Populates all possible fields
        Args:
            xpriv (str): the xpriv
            path (str): the path if it's known. useful for calling derive_path
        Returns:
            (HDKey): the key object
        '''
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
                path=path,
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
        Args:
            pubkey  (bytes): the public key
            network   (str): the network associated
        Returns:
            (HDKey): the key object
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
        '''
        Instantiates an HDKey from a raw privkey
        Args:
            privkey  (bytes): the private key
            network    (str): the network associated
        Returns:
            (HDKey): the key object
        '''
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
        I = hmac.new(  # noqa: E741  # type: ignore
            key=b'Bitcoin seed',
            msg=root_seed,
            digestmod='sha512').digest()  # type: ignore

        # Private key, chain code
        privkey, chain_code = I[:32], I[32:]
        pubkey = simple.priv_to_pub(privkey)
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
        '''
        Makes the xpriv for a master node
        Args:
            privkey    (bytes): the private key
            chain_code (bytes): the chain code
            network      (str): the network
        Returns:
            (str): the xpriv
        '''
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
        '''
        Generates a HDKey object from entropy
        Args:
            entropy         (bytes): 128, 256, or 512 bits
            salt    (str, Optional): an optional salt for derivation
            network (str, Optional): Must be a selection from NETWORK_CODES,
                                     defaults to Bitcoin
        Returns:
            (HDKey)
        '''
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
        '''
        Generates a HDKey object from entropy
        Args:
            mnemonic          (str): the 12+ word mnemonic phrase
            salt    (str, Optional): an optional salt for derivation
            network (str, Optional): Must be a selection from NETWORK_CODES,
                                     defaults to Bitcoin
        Returns:
            (HDKey)
        '''
        root_seed = bip39.root_seed_from_mnemonic(mnemonic, salt, network)
        return HDKey.from_root_seed(root_seed, network)

    @staticmethod
    def _parse_derivation(derivation_path: str) -> List[int]:
        '''
        turns a derivation path (e.g. m/44h/0) into a list of integer indexes
            e.g. [2147483692, 0]
        Args:
            derivation_path (str): the human-readable derivation path
        Returns:
            (list(int)): the derivaion path as a list of indexes
        '''
        int_nodes: List[int] = []

        # Must be / separated
        nodes: List[str] = derivation_path.split('/')
        # If the first node is not m, error.
        # TODO: allow partial path knowledge
        if nodes[0] != 'm':
            raise ValueError('Bad path. Got: {}'.format(derivation_path))

        # Go over all other nodes, and convert to indexes
        nodes = nodes[1:]
        for i in range(len(nodes)):
            if nodes[i][-1] in ['h', "'"]:  # Support 0h and 0' conventions
                int_nodes.append(int(nodes[i][:-1]) + utils.BIP32_HARDEN)
            else:
                int_nodes.append(int(nodes[i]))
        return int_nodes

    def derive_path(self, path: str) -> 'HDKey':
        '''
        Derives a descendant of the current node
        Throws an error if the requested path is not known to be a descendant

        Args:
            path (str): the requested derivation path from master
        Returns:
            (HDKey): the descendant
        '''
        if not self.path:
            raise ValueError('current key\'s path is unknown')

        own_path = cast(str, self.path)
        path_nodes = self._parse_derivation(path)
        my_nodes = self._parse_derivation(own_path)

        # compare own path to requested path see if it is a descendant
        for i in range(len(my_nodes)):
            if my_nodes[i] != path_nodes[i]:
                raise ValueError('requested child not in descendant branches')

        # iteratively derive descendants through the path
        current_node = self
        for i in range(len(my_nodes), len(path_nodes)):
            current_node = current_node.derive_child(path_nodes[i])
        return current_node

    @staticmethod
    def _normalize_index(idx: Union[int, str]) -> int:
        '''
        Normalizes an index so that we can accept ints or strings
        Args:
            idx (int or str): the index as an integer, or a string with h/'
        Returns:
            (int): the index as an integer
        '''
        if type(idx) is int:
            return cast(int, idx)
        if type(idx) is not str:
            raise ValueError('Path index must be string or integer')
        str_idx = cast(str, idx)
        if str_idx[-1] in ['h', "'"]:  # account for h or ' conventions
            return int(str_idx[:-1]) + utils.BIP32_HARDEN
        return int(str_idx)

    def derive_child(self, idx: Union[int, str]) -> 'HDKey':
        '''
        Derives a bip32 child node from the current node
        Args:
            idx (int or str): the index of the child
        Returns:
            (HDKey): the child
        '''
        # TODO: Break up this function

        # normalize the index, error if we can't derive the child
        index: int = self._normalize_index(idx)
        if index >= utils.BIP32_HARDEN and not self.privkey:
            raise ValueError('Need private key to derive hardened children')

        # error if we can't derive a child
        if not self.chain_code:
            raise ValueError('cannot derive child without chain_code')
        else:
            own_chain_code = cast(bytes, self.chain_code)

        # start key derivation process
        data = bytearray()
        index_as_bytes = index.to_bytes(4, byteorder='big')
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
        digest = mac.digest()  # noqa: E741
        tweak, chain_code = digest[:32], digest[32:]
        # end key derivation process

        try:
            child_privkey: Optional[bytes]
            if self.privkey:
                # if we have a private key, give the child a private key
                child_privkey = simple.tweak_privkey_add(self.privkey, tweak)
                child_pubkey = simple.priv_to_pub(child_privkey)
            else:
                # otherwise, just derive a pubkey
                child_privkey = None
                child_pubkey = simple.tweak_pubkey_add(self.pubkey, tweak)
        except Exception:
            # NB: it is possible to derive an "impossible" key.
            #     e.g. the privkey is too high, or is 0
            #     if that happens, the spec says to derive at the next index
            return self.derive_child(index + 1)

        if child_privkey:
            # If we know the privkey, make a new child with the privkey
            child_xpriv = self._make_child_xpriv(
                cast(bytes, child_privkey), index=index, chain_code=chain_code)
            return self._child_from_xpriv(index=index, child_xpriv=child_xpriv)
        else:
            # Otherwise, make a new public child
            child_xpub = self._make_child_xpub(
                child_pubkey, index=index, chain_code=chain_code)
            return self._child_from_xpub(index=index, child_xpub=child_xpub)

    def sign(
            self,
            msg: bytes,
            hash_func: Callable[[bytes], bytes] = utils.sha256) -> bytes:
        '''
        Signs a message with the private key. Errors if no privkey
        Args:
            msg                (bytes): the message to sign
            hash_func (bytes -> bytes): the hash function, defaults to sha2
        Returns:
            (bytes): the signature, DER encoded
        '''
        if not self.privkey:
            raise ValueError('can\t sign without privkey')
        return simple.sign(
            privkey=cast(bytes, self.privkey),
            msg=msg,
            hash_func=hash_func)  # pragma: nocover

    def sign_hash(self, digest: bytes) -> bytes:
        '''
        Signs a hash with the private key. Errors if no privkey
        Args:
            digest (bytes): the message digest to sign. Must be 32 bytes
        Returns:
            (bytes): the signature, DER encoded
        '''
        if not self.privkey:
            raise ValueError('can\t sign without privkey')
        return simple.sign_hash(
            privkey=self.privkey,
            digest=digest)  # pragma: nocover

    def verify(
            self,
            sig: bytes,
            msg: bytes,
            hash_func: Callable[[bytes], bytes] = utils.sha256) -> bool:
        '''
        Verifies a signature on a message
        Args:
            sig                (bytes): the DER-encoded signature
            msg                (bytes): the signed message
            hash_func (bytes -> bytes): the hash function, defaults to sha2
        Returns:
            (bool): True if verified, otherwise False
        '''
        return simple.verify(
            pubkey=self.pubkey,
            sig=sig,
            msg=msg,
            hash_func=hash_func)  # pragma: nocover

    def verify_hash(
            self,
            sig: bytes,
            digest: bytes,
            warn: bool = True) -> bool:  # pragma: nocover
        '''
        Verifies a signature on a message digest
        !!! ECDSA is NOT SECURE unless the verifier calculates the hash  !!!
        Args:
            sig                (bytes): the DER-encoded signature
            digest             (bytes): the digest to verify, must be 32 bytes
        Returns:
            (bool): True if verified, otherwise False
        '''
        # NB: ECDSA is NOT SECURE unless the verifier calculates the hash
        if warn:
            warnings.warn(
                'ECDSA is NOT secure unless the verifier calculates the hash. '
                'Pass warn=False to silence this warning.')
        return simple.verify_hash(
            pubkey=self.pubkey,
            sig=sig,
            digest=digest)
