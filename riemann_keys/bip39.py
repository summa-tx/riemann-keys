import hashlib

from riemann_keys import utils

from typing import List, Tuple


def mnemonic_from_entropy(entropy: bytes):
    '''Entropy -> Mnemonic.
    Args:
        entropy      (bytes): random 128, 160, 192, 224, or 256 bit string
    Returns:
        (str): generated mnemonic
    '''
    validate_entropy(entropy)

    # Number of words in mnemonic
    num_mnemonic = mnemonic_lookup(
        value=len(entropy) * 8,
        value_index=0,
        lookup_index=2)

    # Formatting to convert hex string to binary string
    bit_format = '0{}b'.format(len(entropy) * 8)

    # Convert hex string to binary string
    bit_string = format(int.from_bytes(entropy, 'big'), bit_format)

    # Append binary string with returned checksum digits
    bit_string += checksum(entropy)

    # Number of segments to split bit_string
    segment_len = len(bit_string) // num_mnemonic

    # Split bit_string into segements, each index corresponding to a word
    segments = [
        int(bit_string[i:i + segment_len])
        for i in range(0, len(bit_string), segment_len)
    ]

    return ' '.join(segments_to_mnemonic(segments))


def segments_to_mnemonic(segments) -> List[str]:
    '''Entropy + Checksum Bit Segments -> Mnemonic List.
    Args:
        segments    (list): random 128, 160, 192, 224, or 256 bit string
    Returns:
        (list): mnemonic list
    '''
    word_list = import_word_list()
    index = list(map(lambda seg: int('0b' + str(seg), 2), segments))
    return list(map(lambda i: word_list[i], index))


def root_seed_from_mnemonic(
        mnemonic: str,
        salt: str = None,
        network: str = 'Bitcoin') -> bytes:
    '''Mnemoinc -> 512-bit root seed
    Generates the 512-bit seed as specified in BIP39 given a mnemonic.
    Args:
        mnemonic    (str): 12, 15, 18, 21, 24 words from word list
        salt        (str): optional words for added security
    Returns:
        (bytes): 512-bit root seed
    '''
    validate_mnemonic(mnemonic)
    salt = 'mnemonic' + (salt if salt is not None else '')
    salt_bytes = salt.encode('utf-8')
    mnemonic_bytes = mnemonic.encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic_bytes, salt_bytes, 2048)


def mnemonic_to_bytes(mnemonic: str) -> Tuple[bytes, str]:
    '''Mnemonic -> [bytes]
    Args:
        mnemonic    (str): a 12, 15, 18, 21, or 24 word str
    Returns:
        (bytes): the entropy bytes
          (str): the checksum bits as an bitstring
    '''
    words = mnemonic.split()
    word_list = import_word_list()
    segments = []

    # Convert from mnemonic to entropy + checksum bit-string
    for w in words:
        # Index of word in word list
        idx = word_list.index(w)
        # Map index to 11-bit value
        bits = '{0:011b}'.format(idx)
        # Append 11-bits to segments list
        segments.append(bits)

    # Entropy + checksum bits
    bit_string = ''.join(segments)

    # Number of checksum bits determined by number of words in mnemonic
    checksum_bit_num = mnemonic_lookup(
        value=len(words), value_index=2, lookup_index=1)

    # Checksum bit-string (last bits at end of bit-string)
    checksum_idx = -1 * checksum_bit_num
    checksum_bits = bit_string[checksum_idx:]

    # Entropy bit-string
    bit_string = bit_string[:checksum_idx]

    # Entropy bit-string -> entropy bytes
    b = bytearray()
    for i in range(0, len(bit_string), 8):
        b.append(int(bit_string[i:i + 8], 2))

    return (bytes(b), checksum_bits)


def mnemonic_lookup(value: int, value_index: int, lookup_index: int) -> int:
    '''MNEMONIC_CODES lookup.
    Args:
        value           (int): value to lookup in MNEMONIC_CODES tuple
        value_index     (int): value index of MNEMONIC_CODES tuple
        lookup_index    (int): lookup index of MNEMONIC_CODES tuple
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
        num for num in utils.MNEMONIC_CODES if num[value_index] == value]

    if mnemonic_tuple:
        return mnemonic_tuple[0][lookup_index]

    raise ValueError(
        'Value {} not found at index {} of MNEMONIC_CODES. Value not in {}.'
        .format(
            value,
            value_index,
            ', '.join(
                [str(num[value_index]) for num in utils.MNEMONIC_CODES])))


def import_word_list() -> List[str]:
    '''Imports BIP39 word list.
    Returns:
        (list): 2048 words specified in BIP39
    '''
    from riemann_keys.data.english import WORDS
    return WORDS


def validate_mnemonic(mnemonic: str) -> None:
    '''Validates a mnemonic
    Args:
        mnemonic    (str): potential mnemonic string
    Returns:
        (bool): true if the string is a valid mnemonic, otherwise false
    '''
    # Check the length
    split = mnemonic.split()
    mnem_lens = [c[2] for c in utils.MNEMONIC_CODES]
    if len(split) not in mnem_lens:
        raise ValueError('invalid number of words')

    # Check each word against the list
    words = import_word_list()
    for word in split:
        if word not in words:
            raise ValueError('invalid word in mnemonic')

    # Check the checksum
    entropy_bytes, checksum_bytes = mnemonic_to_bytes(mnemonic)
    if checksum(entropy_bytes) != checksum_bytes:
        raise ValueError('invalid checksum')


def checksum(entropy: bytes) -> str:
    '''Determine checksum and return first segment.
    Args:
        entropy     (bytes): random 128, 160, 192, 224, or 256 bit string
    Returns:
        (byte-str): First checksum segment to be appended to entropy
    '''
    validate_entropy(entropy)

    checksum_len = mnemonic_lookup(
        value=len(entropy) * 8,
        value_index=0,
        lookup_index=1)

    return format(int.from_bytes(
        hashlib.sha256(entropy).digest(), 'big'),
        '0256b')[:checksum_len]


def validate_entropy(entropy: bytes) -> None:
    '''
    Error if entropy is not valid
    '''
    if not isinstance(entropy, bytes):
        raise ValueError('Entropy must be bytes.')

    if len(entropy) not in [16, 20, 24, 28, 32]:
        raise ValueError('Entropy must be 16, 20, 24, 28, or 32 bytes.')
