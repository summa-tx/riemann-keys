import hmac
import hashlib


def pbkdf2_hmac(data, salt=b'', hash_name='sha512', iterations=2048):
    ''' Key stretching function PBKDF2 using HMAC-SHA512 to implement BIP39.
    Args:
        data       (bytes): data to stretch, mnemonic for BIP39
        salt       (bytes): optional data for security, 'mnemonic' for BIP39
        hash_name  (str): HMAC hash digest algorithm, SHA512 for BIP39
        iterations (int): number of HMAC-SHA512 hashing rounds, 2048 for BIP39
    Returns:
        (bytes): generated seed, 512-bit seed for BIP39
    '''
    return hashlib.pbkdf2_hmac(hash_name, data, salt, iterations)


def hmac_sha512(key, msg, digest=hashlib.sha512):
    '''HMAC-SHA512 algorithm to generate master private key and master chain
    code from the root seed entropy + key phrase
    Args:
        key     (bytes): key phrase (ex: 'Bitcoin seed' for Bitcoin network)
        msg     (bytes): root seed entropy
    Returns:
        (bytes): 512-bit hash, I, to get private key and chain code
    '''
    return hmac.digest(key, msg, digest)
