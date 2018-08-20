import os
import pkg_resources
from integral import db, utils
from integral.keys import bip44

DB_PREFIX = b'keys-'
# NB: (bits of entropy, checksum bits, words in mnemonic)
MNEMONIC_CODES = (
    (128, 4, 12),
    (160, 5, 15),
    (192, 6, 18),
    (224, 7, 21),
    (256, 8, 24))


def new_mnemonic(secret_phrase, d):
    '''Generates new 24-word mnemonic and 512-bit seed. Saves to database.
    Args:
        secret_phrase (str): user provided phrase to unencrypt db
        d       (plyvel.DB): db for storing/loading keys
    Returns:
        mnemonic      (str): generated 24-word mnemonic
    '''
    # Generate new 24 word mnemonic
    mnemonic = generate_mnemonic_from_num_words(num_words=24)
    # Save mnemonic to database if does not already exist
    save_mnemonic_to_db(mnemonic, secret_phrase, d)
    return mnemonic


def new_root_seed(mnemonic, secret_phrase, d):
    '''Generates new 512-bit seed. Saves to database.
    Args:
        mnemonic      (str): generated 24-word mnemonic
        secret_phrase (str): user provided phrase to unencrypt db
        d       (plyvel.DB): db for storing/loading keys
    Returns:
        (hex): 512-bit hex string seed as specified in BIP39
    '''
    # Generate 512-bit root seed from user provided mnemonic
    root_seed = generate_seed(mnemonic)
    # Save 512-bit root seed to database
    bip44._save_seed_to_db(root_seed, secret_phrase, d)
    return root_seed


def save_mnemonic_to_db(mnemonic, secret_phrase, d):
    '''Saves mnemonic to database.
    Args:
        mnemonic      (str): string of 24 words
        secret_phrase (str): user provided phrase to unencrypt database
        d       (plyvel.DB): db for storing/loading keys
    Returns:
        (bool): true if saved successfully
    '''
    if not _validate_mnemonic(mnemonic):
        raise ValueError('mnemonic is not properly formatted')
    secret_phrase_hash = bip44._get_secret_phrase_hash(secret_phrase)

    # Mnemonic key database prefix
    key = 'mnemonic-{}'.format(secret_phrase_hash)

    # Check if key already exists in database
    current = db.load_from_db(DB_PREFIX, key, secret_phrase, d)
    if current is not None:
        # If key exists, error.
        return False
    else:
        # If key does not exist, save to database
        db.save_to_db(DB_PREFIX, key, mnemonic, secret_phrase, d)
    # Generate 512-bit root seed from generated mnemonic, save to database
    new_root_seed(mnemonic, secret_phrase, d)
    return True


def load_mnemonic_from_db(secret_phrase, d):
    '''Recovers saved mnemonic from database.
    Args:
        secret_phrase (str): user provided phrase to unencrypt database
    Returns:
        mnemonic (str): string of 24 words
    '''
    if not isinstance(secret_phrase, str):
        raise ValueError('secret_phrase is not a valid hex string.')
    secret_phrase_hash = bip44._get_secret_phrase_hash(secret_phrase)
    key = 'mnemonic-{}'.format(secret_phrase_hash)
    return db.load_from_db(DB_PREFIX, key, secret_phrase, d)


def generate_mnemonic_from_num_words(num_words=24):
    '''Number of words -> Mnemonic from os.urandom entropy.
    Args:
        num_words (int): specify mnemonic length
    Returns:
        (str): generated mnemonic
    '''
    if not isinstance(num_words, int):
        raise ValueError('num_words is not a valid integer type.')
    entropy = os.urandom(_num_words_to_entropy_len(num_words) // 8)
    return _generate_mnemonic(entropy, num_words)


def generate_mnemonic(entropy):
    '''Entropy -> Mnemonic.
    Args:
        entropy   (hex str): random 32, 40, 48, 56, or 64 hex string
    Returns:
        (str): generated mnemonic
    '''
    if not isinstance(entropy, str):
        raise ValueError('Entropy is not a valid hex string.')
    if len(entropy) not in [32, 40, 48, 56, 64]:
        raise ValueError(
            'Entropy must be 128, 160, 192, 224, or 256 bits long.')
    entropy = bytes.fromhex(entropy)
    num_words = _entropy_len_to_num_words(len(entropy) * 8)
    return _generate_mnemonic(entropy, num_words)


def _mnemonic_lookup(value, value_index, lookup_index):
    '''MNEMONIC_CODES lookup.
    Args:
        value         (int): value to lookup in MNEMONIC_CODES tuple
        value_index   (int): value index of MNEMONIC_CODES tuple
        lookup_index  (int): lookup index of MNEMONIC_CODES tuple
    Returns:
        (int): found value in MNEMONIC_CODES tuple lookup_index
    '''
    # Check that entropy is of accepted type
    if not isinstance(value, int):
        raise ValueError('Mnemonic lookup value must be of integer type.')
    if not isinstance(value_index, int):
        raise ValueError('Mnemonic value index must be of integer type.')
    if not isinstance(lookup_index, int):
        raise ValueError('Mnemonic lookup index must be of integer type.')
    # Find corresponding entropy bit length nested tuple
    mnemonic_tuple = [
        num for num in MNEMONIC_CODES if num[value_index] == value]
    if mnemonic_tuple:
        return mnemonic_tuple[0][lookup_index]
    raise ValueError(
        'Value {} not found in index {} of MNEMONIC_CODES. Value not in {}.'
        .format(
            value,
            value_index,
            ', '.join([str(num[value_index]) for num in MNEMONIC_CODES])))


def _entropy_len_to_num_words(entropy_len):
    '''Entropy length -> Number of mnemonic words.
    Args:
        entropy   (int): 128, 160, 192, 224, or 256 entropy bit length
    Returns:
        (int): 12, 15, 18, 21, 24 mnemonic word length
    '''
    return _mnemonic_lookup(value=entropy_len, value_index=0, lookup_index=2)


def _entropy_len_to_checksum_len(entropy_len):
    '''Entropy length -> Checksum length.
    Args:
        entropy   (int): 128, 160, 192, 224, or 256 entropy bit length
    Returns:
        (int): 4, 5, 6, 7, or 8 checksum bit length
    '''
    return _mnemonic_lookup(value=entropy_len, value_index=0, lookup_index=1)


def _num_words_to_entropy_len(num_words):
    '''Number of mnemonic words -> Entropy length.
    Args:
        num_words (int): 12, 15, 18, 21, 24 mnemonic word length
    Returns:
        (int): 128, 160, 192, 224, or 256 entropy bit length
    '''
    return _mnemonic_lookup(value=num_words, value_index=2, lookup_index=0)


def _generate_mnemonic(entropy, num_words):
    '''Entropy -> Mnemonic.
    Args:
        entropy   (bytes): random 128, 160, 192, 224, or 256 bit string
        num_words (int): mnemonic length
    Returns:
        (str): generated mnemonic
    '''
    if not isinstance(entropy, bytes):
        raise ValueError('Entropy must be of type bytes.')
    # Formatting to convert bytes to binary string
    bit_format = '0{}b'.format(len(entropy) * 8)
    # convert bytes to bit string
    bit_string = format(int.from_bytes(entropy, 'big'), bit_format)
    # append bit string with returned checksum digits
    bit_string += _checksum(entropy)
    # number of segments to split bit_string
    segment_len = len(bit_string) // num_words
    # split bit_string into segements, each an index corresponding to a word
    segments = [
        int(bit_string[i:i + segment_len])
        for i in range(0, len(bit_string), segment_len)]
    return ' '.join(_segments_to_mnemonic(segments))


def generate_seed(mnemonic, salt=None):
    '''Mnemoinc -> 512-bit Seed.
    Args:
        mnemonic    (str): 12, 15, 18, 21, 24 words from word list
        salt        (str): 'mnemonic' + optional words for added security
    Returns:
        (hex): 512-bit hex string seed as specified in BIP39
    '''
    salt = 'mnemonic' + (salt if salt is not None else '')
    salt_bytes = salt.encode('utf-8')
    mnemonic_bytes = mnemonic.encode('utf-8')
    return _generate_seed(mnemonic_bytes, salt_bytes).hex()


def _generate_seed(mnemonic_bytes, salt_bytes=b'mnemonic'):
    '''Mnemoinc -> 512-bit Seed.
    Args:
        mnemonic_bytes (bytes): 12, 15, 18, 21, 24 words from word list
        salt_bytes     (bytes): 'mnemonic' + optional words for added security
    Returns:
       (bytes): 512-bit seed as specified in BIP39
    '''
    return utils.pbkdf2_hmac(data=mnemonic_bytes, salt=salt_bytes)


def _checksum(entropy):
    '''Determine checksum and return first segment.
    Args:
        entropy (bytes): random 128, 160, 192, 224, or 256 bit string
    Returns:
        (byte-str): First checksum segment to be appended to entropy
    '''
    if not isinstance(entropy, bytes):
        raise ValueError('Entropy must be of type bytes.')
    cs_len = _entropy_len_to_checksum_len(len(entropy) * 8)
    return format(
        int.from_bytes(utils.sha256(entropy), 'big'), '0256b')[:cs_len]


def _segments_to_mnemonic(segments):
    '''Entropy + Checksum Bit Segments -> Mnemonic List.
    Args:
        segments    (list): random 128, 160, 192, 224, or 256 bit string
    Returns:
        (list): mnemonic list
    '''
    word_list = _import_word_list()
    index = list(map(lambda seg: int('0b' + str(seg), 2), segments))
    return list(map(lambda i: word_list[i], index))


def _mnemonic_to_bytes(mnemonic):
    '''Mnemonic -> [bytes]
    Args:
        mnemonic    (str): a 12, 15, 18, 21, or 24 word str
    Retruns
        (bytes): the entropy bytes
        (str):   the checksum bits as an bitstring
    '''
    words = mnemonic.split()
    word_list = _import_word_list()
    segments = []
    for w in words:
        idx = word_list.index(w)
        bits = '{0:011b}'.format(idx)
        segments.append(bits)

    bit_string = ''.join(segments)
    checksum_bits = _mnemonic_lookup(
        value=len(words), value_index=2, lookup_index=1)

    checksum_idx = -1 * checksum_bits
    checksum_bits = bit_string[checksum_idx:]
    bit_string = bit_string[:checksum_idx]

    b = bytearray()
    for i in range(0, len(bit_string), 8):
        b.append(int(bit_string[i:i + 8], 2))
    return (bytes(b), checksum_bits)


def _import_word_list():
    '''Imports BIP39 word list.
    Returns:
        (list): 2048 words specified in BIP39
    '''
    words = []
    word_list = pkg_resources.resource_string(
        'integral.data',
        'english.txt').decode('utf-8')
    for word in word_list.split('\n')[:-1]:
        words.append(word)
    return words


def _validate_mnemonic(mnemonic):
    '''Validates a mnemonic
    Args:
        mnemonic    (string): a string that might be a mnemonic
    Returns:
        (bool): true if the string is a valid mnemonic, otherwise false
    '''
    # Check the length
    mnem_lens = [c[2] for c in MNEMONIC_CODES]
    split = mnemonic.split()
    words = _import_word_list()
    if len(split) not in mnem_lens:
        return False

    # Check each word against the list
    for word in split:
        if word not in words:
            return False

    # Check the checksum
    entropy_bytes, checksum = _mnemonic_to_bytes(mnemonic)
    if _checksum(entropy_bytes) != checksum:
        return False

    return True
