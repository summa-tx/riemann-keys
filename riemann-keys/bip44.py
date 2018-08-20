from integral import db, utils
from integral.db import DBException
from bip32utils import BIP32Key
from ecdsa.util import sigencode_der_canonize

# https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
# https://github.com/satoshilabs/slips/blob/master/slip-0044.md

BIP32_HARDEN = 2 ** 31
DB_PREFIX = b'keys-'
SECRET_DERIVATION_PATH = 'm/44h/65535/0h'


def _get_secret_phrase_hash(secret_phrase):
    '''
    str -> hex_str
    '''
    return utils.pbkdf2_hmac(
        data=secret_phrase.encode('utf-8'),
        salt=b'integral-db-keying').hex()


def _save_seed_to_db(seed, secret_phrase, d):
    secret_phrase_hash = _get_secret_phrase_hash(secret_phrase)
    key = 'root-{}'.format(secret_phrase_hash)
    current = db.load_from_db(DB_PREFIX, key, secret_phrase, d)
    if current is not None:
        raise DBException('Refusing to overwrite HD root node')
    else:
        db.save_to_db(DB_PREFIX, key, seed, secret_phrase, d)
        return True


def load_seed_from_db(secret_phrase, d):
    '''
    str -> hex_str
    '''
    secret_phrase_hash = _get_secret_phrase_hash(secret_phrase)
    key = 'root-{}'.format(secret_phrase_hash)

    return db.load_from_db(DB_PREFIX, key, secret_phrase, d)


def load_root_node_from_db(secret_phrase, d):
    '''
    str -> hex_str
    '''
    seed = load_seed_from_db(secret_phrase, d)
    return BIP32Key.fromEntropy(bytes.fromhex(seed))


def _parse_derivation(derivation_path):
    '''
    str -> list(int)
    turns a derivation path (e.g. m/44h/0) into a list of integers
    '''
    nodes = derivation_path.split('/')
    if nodes[0] != 'm':
        raise ValueError('Bad path. Got: {}'.format(derivation_path))
    nodes = nodes[1:]
    for i in range(len(nodes)):
        if nodes[i][-1] in ['h', "'"]:  # Support 0h and 0' conventions
            nodes[i] = int(nodes[i][:-1]) + BIP32_HARDEN
        else:
            nodes[i] = int(nodes[i])
    return nodes


# The external key is the external node in the derivation tree
# The external key is used to communicate (i.e. external uses)
# The internal key is used for change addresses and other internal uses
def _get_coin_external_key(coin_deriv_path, secret_phrase, d):
    '''
    str, str -> hex_str
    '''
    current = load_root_node_from_db(secret_phrase, d)
    nodes = _parse_derivation(coin_deriv_path)
    for node in nodes:
        current = current.ChildKey(node)
    coin_external_node = current.ChildKey(0)
    return coin_external_node


def next_derivation_path(coin_deriv_path, secret_phrase, d):
    '''
    str, str -> hex_str
    '''
    secret_phrase_hash = _get_secret_phrase_hash(secret_phrase)
    key = '{}-{}'.format(coin_deriv_path, secret_phrase_hash)

    # Get and update the index
    last_index = db.load_from_db(DB_PREFIX, key, secret_phrase, d)
    if last_index is None:
        current_index = 0
    else:
        current_index = int(last_index) + 1
    db.save_to_db(DB_PREFIX, key, str(current_index), secret_phrase, d)

    return '{derivation}/0/{index}'.format(
        derivation=coin_deriv_path,
        index=current_index)


def key_from_derivation(derivation, secret_phrase, d):
    '''
    str, str -> hex_str
    '''
    key_obj = signing_key_from_derivation(derivation, secret_phrase, d)
    return key_obj.PrivateKey().hex()


def signing_key_from_derivation(derivation, secret_phrase, d):
    '''
    str, str -> bip32utils.BIP32Key
    '''
    nodes = _parse_derivation(derivation)
    current = load_root_node_from_db(secret_phrase, d)
    for node in nodes:
        current = current.ChildKey(node)
    return current


def pubkey_from_derivation(derivation, secret_phrase, d):
    '''
    str, str -> hex_str
    '''
    nodes = _parse_derivation(derivation)
    current = load_root_node_from_db(secret_phrase, d)
    for node in nodes:
        current = current.ChildKey(node)
    return current.PublicKey().hex()


def next_secret_derivation(secret_phrase, d):
    '''
    str -> str
    '''
    secret_phrase_hash = _get_secret_phrase_hash(secret_phrase)
    key = 'secret-{}'.format(secret_phrase_hash)

    # Get and update the index
    last_index = db.load_from_db(DB_PREFIX, key, secret_phrase, d)
    if last_index is None:
        current_index = 0
    else:
        current_index = int(last_index) + 1
    db.save_to_db(DB_PREFIX, key, str(current_index), secret_phrase, d)
    return '{derivation}/0/{index}'.format(
        derivation=SECRET_DERIVATION_PATH,
        index=current_index)


def secret_from_derivation(derivation, secret_phrase, d):
    '''
    str, str -> hex_str
    '''
    nodes = _parse_derivation(derivation)
    current = load_root_node_from_db(secret_phrase, d)
    for node in nodes:
        current = current.ChildKey(node)
    return current.PrivateKey().hex()


def sign_hash_with_derivation(sighash, derivation, secret_phrase, d):
    '''
    bytes, str, str -> hex_str
    signs a hash with the key at the specified derivation
    signatures are bitcoin compatible (canonized)
    '''
    key = signing_key_from_derivation(derivation, secret_phrase, d)
    return key.k.sign_digest(sighash, sigencode=sigencode_der_canonize).hex()


def next_derivation_and_pubkey(coin_deriv_path, secret_phrase, d):
    '''
    str, str -> tuple(str, hex_str)
    returns the next unused derivation path and pubkey for a coin
    '''
    derivation = next_derivation_path(coin_deriv_path, secret_phrase, d)
    pubkey = pubkey_from_derivation(derivation, secret_phrase, d)
    return (derivation, pubkey)


def next_secret_derivation_and_hash(secret_phrase, d):
    '''
    str, str -> tuple(str, hex_str)
    returns the next unused derivation path and hash for a secret
    '''
    derivation = next_secret_derivation(secret_phrase, d)
    secret = secret_from_derivation(derivation, secret_phrase, d)
    secret_hash = utils.sha256(bytes.fromhex(secret)).hex()
    return (derivation, secret_hash)


def get_derivation_by_contract_address(
        address, coin_deriv_path, secret_phrase, d):
    '''
    str, str, str -> tuple(str, hex_str)
    returns a (derivation, pubkey) tuple
    unique per secret phrase + contract address
    if one does not exist, we make one
    if one already exists, we return it
    '''
    secret_phrase_hash = _get_secret_phrase_hash(secret_phrase)
    key = 'contract-{}-{}'.format(address, secret_phrase_hash)
    derivation = db.load_from_db(DB_PREFIX, key, secret_phrase, d)
    if derivation is None:
        (derivation, pubkey) = next_derivation_and_pubkey(
            coin_deriv_path=coin_deriv_path,
            secret_phrase=secret_phrase,
            d=d)
        db.save_to_db(DB_PREFIX, key, derivation, secret_phrase, d)
    else:
        pubkey = pubkey_from_derivation(derivation, secret_phrase, d)
    return (derivation, pubkey)
