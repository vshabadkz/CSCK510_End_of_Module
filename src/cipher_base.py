import random
import string
from secretpy import ADFGVX, ColumnarTransposition, Zigzag, CryptMachine

def generate_polybius_square(init_vector):
    """Generate a randomized polybius square using the initialization vector"""
    random.seed(init_vector)
    chars = list(string.ascii_lowercase)
    random.shuffle(chars)
    return "".join(chars)

def initialize_ciphers(init_vector, keyword):
    """Initialize all ciphers with their configurations"""
    return [
        ('ADFGVX', ADFGVX(), generate_polybius_square(init_vector), keyword),
        ('Columnar', ColumnarTransposition(), None, keyword),
        ('Railfence', Zigzag(), None, 3)
    ]

def create_cipher_machine(cipher, key, alphabet=None):
    """Create and configure a cipher machine"""
    cm = CryptMachine(cipher)
    cm.set_key(key)
    if alphabet:
        cm.set_alphabet(alphabet)
    return cm