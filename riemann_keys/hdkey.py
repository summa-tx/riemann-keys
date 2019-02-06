import hmac
import hashlib

# import secpy256k1
from secpy256k1 import simple

from riemann_keys import base58, bip39, utils

from typing import cast, List, Optional
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

    def __repr__(self):
        return '{}{}'.format(
            self.xpub if self.xpub else self.pubkey.hex(),
            ' with privkey' if self.privkey is not None else '')

    def _child_from_xpub(self, index: int, xpub: str) -> 'HDKey':
        path: Optional[str]
        if self.path:
            path = '{}/{}'.format(self.path, str(index))
        else:
            path = None
        xpub_bytes = base58.decode(xpub)
        pubkey = xpub_bytes[45:78]

        if xpub_bytes[0:4] == b'\x04\x88\xb2\x1e':
            network = 'Bitcoin'
        elif xpub_bytes[0:4] == b'\x04\x35\x87\xcf':
            network = 'Testnet'
        else:
            raise ValueError('unrecognized version bytes. Is this an xpub?')

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
                xpub=xpub,
                privkey=None,
                pubkey=pubkey),
            _error_on_call=False)

    def _child_from_xpriv(self, index: int, xpriv: str) -> 'HDKey':
        path: Optional[str]
        if self.path:
            if index >= utils.BIP32_HARDEN:
                index_str = '{}h'.format(str(index - utils.BIP32_HARDEN))
            else:
                index_str = str(index)
            path = '{}/{}'.format(self.path, index_str)
        else:
            path = None

        xpriv_bytes = base58.decode(xpriv)
        privkey = xpriv_bytes[46:78]
        pubkey = simple.priv_to_pub(privkey)

        if xpriv_bytes[0:4] == b'\x04\x88\xad\xe4':
            network = 'Bitcoin'
        elif xpriv_bytes[0:4] == b'\x04\x35\x83\x94':
            network = 'Testnet'
        else:
            raise ValueError('unrecognized version bytes. Is this an xpriv?')

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
                xpriv=xpriv,
                xpub=HDKey._xpriv_to_xpub(xpriv),
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
        xpub.extend([cast(int, self.depth)])
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
        xpriv.extend([cast(int, self.depth)])
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

        if xpriv_bytes[0:4] == b'\x04\x88\xad\xe4':
            # mainnet
            xpub.extend(b'\x04\x88\xb2\x1e')
        elif xpriv_bytes[0:4] == b'\x04\x35\x83\x94':
            # testnet
            xpub.extend(b'\x04\x35\x87\xcf')
        else:
            raise ValueError('unrecognized version bytes. Is this an xpub?')

        # verbatim
        xpub.extend(xpriv_bytes[4:45])

        # derive the pubkey
        xpub.extend(simple.priv_to_pub(xpriv_bytes[46:78]))

        return base58.encode(xpub)

    @classmethod
    def from_xpub(HDKey, xpub: str) -> 'HDKey':
        xpub_bytes = base58.decode(xpub)
        pubkey = xpub_bytes[45:78]

        if xpub_bytes[0:4] == b'\x04\x88\xb2\x1e':
            network = 'Bitcoin'
        elif xpub_bytes[0:4] == b'\x04\x35\x87\xcf':
            network = 'Testnet'
        else:
            raise ValueError('unrecognized version bytes. Is this an xpub?')

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

        if xpriv_bytes[0:4] == b'\x04\x88\xad\xe4':
            network = 'Bitcoin'
        elif xpriv_bytes[0:4] == b'\x04\x35\x83\x94':
            network = 'Testnet'
        else:
            raise ValueError('unrecognized version bytes. Is this an xpriv?')

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
        version = b'\x04\x88\xad\xe4' if network == 'Bitcoin' \
                  else b'\x04\x35\x83\x94'
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
                int_nodes[i] = int(nodes[i][:-1]) + utils.BIP32_HARDEN
            else:
                int_nodes[i] = int(nodes[i])
        return int_nodes

    def derive_path(self, path: str):
        '''
        derives a descendant of the current node
        '''
        if not self.path:
            raise ValueError('current key\'s path is unknown')
        own_path = cast(str, self.path)
        if path.find(own_path) == -1:
            raise ValueError('requested child not in descendant branches')
        path_nodes = self._parse_derivation(path)
        my_nodes = self._parse_derivation(own_path)

        current_node = self
        for i in range(len(my_nodes), len(path_nodes)):
            current_node = current_node.derive_child(path_nodes[i])
        return current_node

    def derive_child(self, index: int):
        '''
        Derives a bip32 child from the current node
        '''
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
            if self.privkey:
                child_privkey = simple.tweak_privkey_add(self.privkey, IL)
            else:
                child_privkey = None
                child_pubkey = simple.tweak_pubkey_add(self.pubkey, IL)
        except Exception:
            return self.derive_child(index + 1)

        if child_privkey:
            xpriv = self._make_child_xpriv(
                child_privkey, index=index, chain_code=IR)
            return self._child_from_xpriv(index=index, xpriv=xpriv)
        else:
            xpub = self._make_child_xpub(
                child_pubkey, index=index, chain_code=IR)
            return self._child_from_xpub(index=index, xpub=xpub)


# class HDKeyy:
#
#     def __init__(self, **kwargs):
#         self._c_private_key = None
#         self._c_public_key = None
#         self.child = None
#         self.path = kwargs.get("path", "m")
#         self.depth = kwargs.get("depth", 0)
#         self.index = kwargs.get("index")
#         self.network = kwargs.get("network", "Bitcoin")
#         self.parent = kwargs.get("parent")
#         self.chain_code = kwargs.get("chain_code")
#         self.fingerprint = kwargs.get("fingerprint")
#         # self.extended_private_key = kwargs.get("extended_private_key")
#
#     @property
#     def public_key(self) -> bytes:
#         if self._c_public_key is None:
#             return None
#
#         c_public_key = secpy256k1.ec_pubkey_serialize(
#             utils.CONTEXT_VERIFY, self._c_public_key, utils.COMPRESSED
#         )[1]
#
#         return self.convert_to_bytes(c_public_key)
#
#     @public_key.setter
#     def public_key(self, pubkey):
#         if pubkey is None:
#             return
#         if type(pubkey) != bytes:
#             raise TypeError("Public key must be of type bytes")
#         if len(pubkey) != 33 and len(pubkey) != 65:
#             raise ValueError("Public key must be either 33 or 65 bytes")
#
#         c_pubkey = secpy256k1.ec_pubkey_parse(
#             utils.VERIFY_CONTEXT, pubkey)[1]
#         self._c_public_key = c_pubkey
#
#     @property
#     def private_key(self):
#         if self._c_private_key is None:
#             return None
#
#         return self.convert_to_bytes(self._c_private_key, True)
#
#     @private_key.setter
#     def private_key(self, privkey):
#         if privkey is None:
#             return
#         if type(privkey) != bytes:
#             raise TypeError("Private key must be of type bytes")
#         if len(privkey) != 32:
#             raise ValueError("Private key must be 32 bytes")
#         if secpy256k1.ec_seckey_verify(self.CONTEXT_SIGN, privkey) != 1:
#             raise Exception("Secp256k1 verify failed")
#
#         # store in c buffer
#         c_private_key = secpy256k1.ffi.new("char[]", privkey)
#         self._c_private_key = c_private_key
#
#         # Derive public key from private
#         c_unser_public_key = secpy256k1.ec_pubkey_create(
#             ctx=self.CONTEXT_SIGN,
#             seckey=privkey
#         )[1]
#
#         self._c_public_key = c_unser_public_key
#
#     @property
#     def extended_private_key(self):
#         xpriv = b""
#         if self.network == "Testnet":
#             xpriv += b"\x04\x35\x83\x94"
#         else:
#             xpriv += b"\x04\x88\xAD\xE4"
#
#         xpriv += bytes(chr(self.depth), 'utf8')
#         xpriv += self.parent.fingerprint if self.parent else b"\x00\x00\x00\00"
#         xpriv += int(self.index).to_bytes(4, byteorder="big")
#         xpriv += self.chain_code
#         xpriv += b"\x00" + self.private_key
#
#         # checksum
#         sha1 = hashlib.sha256(xpriv).digest()
#         sha2 = hashlib.sha256(sha1).digest()
#         xpriv += sha2[:4]
#
#         return base58.encode(xpriv).decode("utf-8")
#
#     @extended_private_key.setter
#     def extended_private_key(self, xpriv):
#         if type(xpriv) != bytes:
#             raise TypeError("Xpriv must be of type bytes")
#
#         decoded_xpriv = base58.decode(xpriv)
#         if decoded_xpriv[:4] == b"\x04\x35\x83\x94":
#             self.network = "Testnet"
#         elif (decoded_xpriv[:4] == b"\x04\x88\xB2\x1E"
#                 or decoded_xpriv[:4] == b"\x04\x35\x87\xCF"):
#             raise ValueError("Xpub provided instead of xpriv")
#
#         self.depth = decoded_xpriv[4]
#         self.fingerprint = decoded_xpriv[5:9]
#         self.index = decoded_xpriv[9:13].hex()
#         self.chain_code = decoded_xpriv[13:45]
#         self.private_key = decoded_xpriv[46:78]  # skip 45 since it's a pad
#
#     @property
#     def extended_public_key(self):
#         xpub = b""
#         if self.network == "Testnet":
#             xpub += b"\x04\x35\x87\xCF"
#         else:
#             xpub += b"\x04\x88\xB2\x1E"
#
#         xpub += bytes(chr(self.depth), 'utf8')
#         xpub += self.parent.fingerprint if self.parent else b"\x00\x00\x00\00"
#         xpub += int(self.index).to_bytes(4, byteorder="big")
#         xpub += self.chain_code
#         xpub += self.public_key
#
#         return base58.encode(xpub)
#
#     @extended_public_key.setter
#     def extended_public_key(self, xpub):
#         if type(xpub) != bytes:
#             raise TypeError("Xpub must be of type bytes")
#
#         decoded_xpub = base58.decode(xpub)
#         if decoded_xpub[:4] == b"\x04\x35\x87\xCF":
#             self.network = "Testnet"
#         elif (decoded_xpub[:4] == b"\x04\x88\xAD\xE4"
#                 or decoded_xpub[:4] == b"\x04\x35\x83\x94"):
#             raise ValueError("Xpriv provided instead of xpub")
#
#         self.depth = decoded_xpub[4]
#         self.fingerprint = decoded_xpub[5:9]
#         self.index = decoded_xpub[9:13].hex()
#         self.chain_code = decoded_xpub[13:45]
#         self.public_key = decoded_xpub[45:78]
#
#     @property
#     def fingerprint(self):
#         """ Returns fingerprint as 4 byte hex """
#         if self._fingerprint is None:
#             self._fingerprint = self.hash160(self.public_key)[:4]
#
#         return self._fingerprint
#
#     @fingerprint.setter
#     def fingerprint(self, fingerprint):
#         """ Stores fingerprint as bytes """
#         if ((type(fingerprint) == bytes and len(fingerprint) == 4)
#                 or fingerprint is None):
#             self._fingerprint = fingerprint
#         elif type(fingerprint) == int:
#             self._fingerprint = (fingerprint).to_bytes(4, byteorder='big')
#         else:
#             raise TypeError("Fingerprint must be either int or bytes")
#
#     def derive_path(self, path):
#         if len(path) == 0:
#             return self
#         if isinstance(path, str):
#             path = path.split("/")
#
#         assert path[-1] != '', "Malformed Path"
#
#         current_node = path.pop(0)
#         if (
#             (
#                 current_node.lower() == "m"
#                 or current_node.lower() == "m'"
#             )
#             and len(path) == 0
#         ):
#             return self
#         elif current_node.lower() == "m" or current_node.lower() == "m'":
#             return self.derive_path(path)
#
#         child = self.derive_child(current_node)
#         child.path = self.path + "/" + str(current_node)
#         child.parent = self
#         self.child = child
#
#         return child.derive_path(path)
#
#     def derive_child(self, index):
#         """
#             Derives the immediate child to the index provided
#             Args:
#                 index: (string)
#             Returns:
#                 (HDKey)
#         """
#         hardened = False
#         if "'" in index:
#             index = int(index[:-1]) + 0x80000000  # 0x80000000 == 2^31,
#             hardened = True
#
#         index_serialized_32 = int(index).to_bytes(4, byteorder="big")
#
#         if hardened:
#             if (self.private_key is None):
#                 raise Exception(
#                     "Private Key is needed for to derive hardened children"
#                 )
#
#             # Data = 0x00 || ser256(kpar) || ser32(i)
#             # (Note: The 0x00 pads the private key to make it 33 bytes long.)
#             data = b"".join([b"\x00" + self.private_key, index_serialized_32])
#         else:
#             # Data = serP(point(kpar)) || ser32(i)).
#             data = b"".join([self.public_key, index_serialized_32])
#
#         # I = HMAC-SHA512(Key = cpar, Data)
#         I = hmac.new(self.chain_code, digestmod=hashlib.sha512)  # noqa: E741
#         I.update(data)
#         I = I.digest()  # noqa: E741
#         IL, IR = I[:32], I[32:]
#
#         child = HDKey(
#             parent=self,
#             network=self.network,
#             path=self.path + "/" + str(index),
#             index=index,
#             depth=self.depth + 1
#         )
#
#         # Private parent key -> private child key
#         if self.private_key:
#             check, child.private_key = secpy256k1.ec_privkey_tweak_add(
#                 ctx=self.CONTEXT_SIGN,
#                 seckey=self.private_key,
#                 tweak=IL
#             )
#             if (check == 0):
#                 # In case parse256(IL) ≥ n or ki = 0, the resulting key is
#                 # invalid, and one should proceed with the next value for i.
#                 # (Note: this has probability lower than 1 in 2^127.)
#                 return HDKey.derive_child(index + 1, hardened)
#
#         # Public parent key -> public child key
#         else:
#             check, child.public_key = secpy256k1.ec_pubkey_tweak_add(
#                 ctx=self.CONTEXT_SIGN,
#                 pubkey=self.public_key,
#                 tweak=IL
#             )
#             if (check == 0):
#                 return HDKey.derive_child(index + 1, hardened)
#
#         child.chain_code = IR
#         return child
#
#     @staticmethod
#     def from_entropy(entropy, network='Bitcoin'):
#         '''
#         Generates a HDKey object given entropy.
#         Args:
#             entropy (bytes): 128, 160, 192, 224, or 256 bits
#         Returns:
#             (HDKey)
#         '''
#         # WIP
#         HDKey.validate_entropy(entropy)
#
#         # Generate mnemonic to get root seed
#         mnemonic = HDKey.mnemonic_from_entropy(entropy)
#
#         # Generate root seed to build HDKey
#         root_seed = HDKey.root_seed_from_mnemonic(mnemonic, network)
#
#         # Generate master keys and chain code from root_seed
#         return HDKey.from_root_seed(root_seed, network)
#
#     @staticmethod
#     def from_root_seed(root_seed, network='Bitcoin'):
#         '''
#         Generates a HDKey object given the root seed.
#         Args:
#             root_seed (bytes):          128, 256, or 512 bits
#             network (str, Optional):    Must be a selection from NETWORK_CODES,
#                                         defaults to Bitcoin
#         Returns:
#             (HDKey)
#         '''
#         # WIP
#         # TODO: get key depending on network
#         # data/key, msg, digest
#         I = hmac.new(  # noqa: E741
#             key=b'Bitcoin seed',
#             msg=root_seed,
#             digestmod=hashlib.sha512
#         ).digest()
#
#         # Private key, chain code
#         I_left, I_right = I[:32], I[32:]
#
#         root = HDKey(
#             network=network,
#             chain_code=I_right,
#             depth=0,
#             index=0,
#             path='m/'
#         )
#         root.private_key = I_left
#         return root
#
#     @staticmethod
#     def from_mnemonic(mnemonic, salt=None, network='Bitcon'):
#         '''
#         Generate a HDKey object given a mnemonic.
#         Args:
#             mnemonic    (str): 12, 15, 18, 21, 24 words from word list
#             salt        (str): optional words for added security
#             network (WIP)
#         Returns:
#             (HDKey)
#         '''
#         root_seed = HDKey.root_seed_from_mnemonic(mnemonic, salt, network)
#         return HDKey.from_root_seed(root_seed, network)
#
#     @staticmethod
#     def mnemonic_from_entropy(entropy: bytes):
#         '''Entropy -> Mnemonic.
#         Args:
#             entropy      (bytes): random 128, 160, 192, 224, or 256 bit string
#             num_mnemonic (int): mnemonic length
#         Returns:
#             (str): generated mnemonic
#         '''
#         HDKey.validate_entropy(entropy)
#
#         # Number of words in mnemonic
#         num_mnemonic = HDKey.mnemonic_lookup(
#             value=len(entropy) * 8,
#             value_index=0,
#             lookup_index=2
#         )
#
#         # Formatting to convert hex string to binary string
#         bit_format = '0{}b'.format(len(entropy) * 8)
#
#         # Convert hex string to binary string
#         bit_string = format(int.from_bytes(entropy, 'big'), bit_format)
#
#         # Append binary string with returned checksum digits
#         bit_string += HDKey.checksum(entropy)
#
#         # Number of segments to split bit_string
#         segment_len = len(bit_string) // num_mnemonic
#
#         # Split bit_string into segements, each index corresponding to a word
#         segments = [
#             int(bit_string[i:i + segment_len])
#             for i in range(0, len(bit_string), segment_len)
#         ]
#
#         return ' '.join(HDKey.segments_to_mnemonic(segments))
#
#     @staticmethod
#     def segments_to_mnemonic(segments):
#         '''Entropy + Checksum Bit Segments -> Mnemonic List.
#         Args:
#             segments    (list): random 128, 160, 192, 224, or 256 bit string
#         Returns:
#             (list): mnemonic list
#         '''
#         word_list = HDKey.import_word_list()
#         index = list(map(lambda seg: int('0b' + str(seg), 2), segments))
#         return list(map(lambda i: word_list[i], index))
#
#     @staticmethod
#     def root_seed_from_mnemonic(mnemonic, salt=None, network='Bitcoin'):
#         '''Mnemoinc -> 512-bit root seed
#         Generates the 512-bit seed as specified in BIP39 given a mnemonic.
#         Args:
#             mnemonic    (str): 12, 15, 18, 21, 24 words from word list
#             salt        (str): optional words for added security
#         Returns:
#             (bytes): 512-bit root seed
#         '''
#         HDKey.validate_mnemonic(mnemonic)
#         salt = 'mnemonic' + (salt if salt is not None else '')
#         salt_bytes = salt.encode('utf-8')
#         mnemonic_bytes = mnemonic.encode('utf-8')
#         return hashlib.pbkdf2_hmac('sha512', mnemonic_bytes, salt_bytes, 2048)
#
#     @staticmethod
#     def mnemonic_to_bytes(mnemonic):
#         '''Mnemonic -> [bytes]
#         Args:
#             mnemonic    (str): a 12, 15, 18, 21, or 24 word str
#         Returns:
#             (bytes): the entropy bytes
#               (str): the checksum bits as an bitstring
#         '''
#         words = mnemonic.split()
#         word_list = HDKey.import_word_list()
#         segments = []
#
#         # Convert from mnemonic to entropy + checksum bit-string
#         for w in words:
#             # Index of word in word list
#             idx = word_list.index(w)
#             # Map index to 11-bit value
#             bits = '{0:011b}'.format(idx)
#             # Append 11-bits to segments list
#             segments.append(bits)
#
#         # Entropy + checksum bits
#         bit_string = ''.join(segments)
#
#         # Number of checksum bits determined by number of words in mnemonic
#         checksum_bits = HDKey.mnemonic_lookup(
#             value=len(words), value_index=2, lookup_index=1)
#
#         # Checksum bit-string (last bits at end of bit-string)
#         checksum_idx = -1 * checksum_bits
#         checksum_bits = bit_string[checksum_idx:]
#
#         # Entropy bit-string
#         bit_string = bit_string[:checksum_idx]
#
#         # Entropy bit-string -> entropy bytes
#         b = bytearray()
#         for i in range(0, len(bit_string), 8):
#             b.append(int(bit_string[i:i + 8], 2))
#
#         return (bytes(b), checksum_bits)
#
#     @staticmethod
#     def mnemonic_lookup(value, value_index, lookup_index):
#         '''MNEMONIC_CODES lookup.
#         Args:
#             value           (int): value to lookup in MNEMONIC_CODES tuple
#             value_index     (int): value index of MNEMONIC_CODES tuple
#             lookup_index    (int): lookup index of MNEMONIC_CODES tuple
#         Returns:
#             (int): found value in MNEMONIC_CODES tuple lookup_index
#         '''
#         # Check that entropy is of accepted type
#         if not isinstance(value, int):
#             raise ValueError('Mnemonic lookup value must be of integer type.')
#
#         if not isinstance(value_index, int):
#             raise ValueError('Mnemonic value index must be of integer type.')
#
#         if not isinstance(lookup_index, int):
#             raise ValueError('Mnemonic lookup index must be of integer type.')
#
#         # Find corresponding entropy bit length nested tuple
#         mnemonic_tuple = [
#             num for num in HDKey.MNEMONIC_CODES if num[value_index] == value]
#
#         if mnemonic_tuple:
#             return mnemonic_tuple[0][lookup_index]
#
#         raise ValueError(
#             'Value {} not found in index {} of MNEMONIC_CODES.Value not in {}.'
#             .format(
#                 value,
#                 value_index,
#                 ', '.join(
#                     [str(num[value_index]) for num in HDKey.MNEMONIC_CODES])))
#
#     @staticmethod
#     def import_word_list():
#         '''Imports BIP39 word list.
#         Returns:
#             (list): 2048 words specified in BIP39
#         '''
#         words = []
#
#         # Import mnemonic words
#         #  with open('./data/english.txt', 'r') as f:
#         #      word_list = f.read()
#         # Import mnemonic words
#         word_list = pkg_resources.resource_string(
#             'riemann_keys', 'data/english.txt').decode('utf-8')
#
#         # Create mnemonic word list
#         for word in word_list.split('\n')[:-1]:
#             words.append(word)
#
#         return words
#
#     @staticmethod
#     def validate_mnemonic(mnemonic):
#         '''Validates a mnemonic
#         Args:
#             mnemonic    (string): potential mnemonic string
#         Returns:
#             (bool): true if the string is a valid mnemonic, otherwise false
#         '''
#         # Check the length
#         mnem_lens = [c[2] for c in HDKey.MNEMONIC_CODES]
#         split = mnemonic.split()
#         words = HDKey.import_word_list()
#         if len(split) not in mnem_lens:
#             return False
#
#         # Check each word against the list
#         for word in split:
#             if word not in words:
#                 return False
#
#         # Check the checksum
#         entropy_bytes, checksum = HDKey.mnemonic_to_bytes(mnemonic)
#         if HDKey.checksum(entropy_bytes) != checksum:
#             return False
#
#         return True
#
#     @staticmethod
#     def checksum(entropy):
#         '''Determine checksum and return first segment.
#         Args:
#             entropy     (bytes): random 128, 160, 192, 224, or 256 bit string
#         Returns:
#             (byte-str): First checksum segment to be appended to entropy
#         '''
#         HDKey.validate_entropy(entropy)
#
#         checksum_len = HDKey.mnemonic_lookup(
#             value=len(entropy) * 8,
#             value_index=0,
#             lookup_index=1)
#
#         return format(int.from_bytes(
#             hashlib.sha256(entropy).digest(), 'big'),
#             '0256b')[:checksum_len]
#
#     @staticmethod
#     def validate_entropy(entropy):
#         if not isinstance(entropy, bytes):
#             raise ValueError('Entropy must be bytes.')
#
#         len_e = len(entropy)
#         if len_e not in list(map(lambda x: x // 8, [128, 160, 192, 224, 256])):
#             raise ValueError('Entropy must be 16, 20, 24, 28, or 32 bytes.')
#
#         return True
#
#     @staticmethod
#     def convert_to_bytes(key, pop_newline=False):
#         byte_form = bytes(secpy256k1.ffi.buffer(key))
#         if pop_newline:
#             return byte_form[:-1]
#
#         return byte_form
