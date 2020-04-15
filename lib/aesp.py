# Access functions from c library
from ctypes import *
sofilename = "/home/daniel/Projects/cryptopals/lib/aes.so"
aes = CDLL(sofilename)
BLOCK_SIZE = 16

# AES functions
def pad( text ):
    """Adds padding to a string of bytes to make it a multiple of BLOCK_SIZE."""
    r = len(text)%BLOCK_SIZE
    to_add = BLOCK_SIZE - r if r != 0 else 0
    return text + b'\x04'*(to_add)

def AES_ECB_encrypt( plaintext, key ):
    """Encrypts the plaintext using a 128 bit key in ECB mode. Plaintext is 
    automatically padded as necessary."""
    # Make a copy of plaintext so it doesn't get changed
    plainbytes = bytes([ x for x in plaintext ])
    # Pad the plaintext to a multiple of BLOCK_SIZE
    plainbytes = pad(plainbytes)

    ciphertext= b''
    cipherblock = create_string_buffer(BLOCK_SIZE)
    for i in range( len(plainbytes) // BLOCK_SIZE ):
        aes.AESencrypt( plainbytes[BLOCK_SIZE*i : BLOCK_SIZE*i+BLOCK_SIZE], key, cipherblock )
        ciphertext += bytes(cipherblock)
        # Note! Don't use cipherblock.value! This will incorrectly terminate if 
        # there is a \00
    return ciphertext

def AES_ECB_decrypt( ciphertext, key ):
    """Decrypts the ciphertext using a 128 bit key in ECB mode."""
    # Decrypt the ciphertext one block at a time
    plaintext = b''
    plainblock = create_string_buffer(BLOCK_SIZE)
    cipherblock = create_string_buffer(BLOCK_SIZE)
    for i in range(len(ciphertext) // BLOCK_SIZE):
        cipherblock = ciphertext[BLOCK_SIZE*i : BLOCK_SIZE*i+BLOCK_SIZE]
        aes.AESdecrypt( cipherblock, key, plainblock )
        plaintext += bytes(plainblock)
    return plaintext

def AES_CBC_encrypt( plaintext, key, IV ):
    """Encrypts the plaintext using a 128 bit key and initialisation 
    vector. Plaintext is automatically padded as necessary."""
    # Make a copy of plaintext so it doesn't get changed
    plainbytes = bytes([ x for x in plaintext ])
    # Pad the plaintext to a multiple of BLOCK_SIZE
    plainbytes = pad(plainbytes)

    ciphertext= b''
    cipherblock = create_string_buffer(BLOCK_SIZE)
    for i in range( len(plainbytes) // BLOCK_SIZE ):
        plainblock = plainbytes[BLOCK_SIZE*i : BLOCK_SIZE*i+BLOCK_SIZE]
        # xor plaintext and IV
        plainblock = bytes([ a^b for (a,b) in zip(plainblock, IV) ])
        # Encrypt with key
        aes.AESencrypt( plainblock, key, cipherblock )
        # Update IV
        IV = bytes(cipherblock)
        # Append ciphertext
        ciphertext += bytes(cipherblock)
        # Note! Don't use cipherblock.value! This will incorrectly terminate if 
        # there is a \00
    return ciphertext

def AES_CBC_decrypt( ciphertext, key, IV ):
    """Decrypts the ciphertext using a 128 bit key and initialisation vector."""
    plaintext = b''
    cipherblock = create_string_buffer(BLOCK_SIZE)
    preplainblock = create_string_buffer(BLOCK_SIZE)
    plainblock = [0]*16
    for i in range(len(ciphertext) // BLOCK_SIZE):
        cipherblock = ciphertext[BLOCK_SIZE*i : BLOCK_SIZE*i+BLOCK_SIZE]
        # Decrypt block using key
        aes.AESdecrypt( cipherblock, key, preplainblock )
        # xor with IV to get plaintext
        plainblock = bytes([ ord(a)^b for (a,b) in zip(preplainblock, IV) ])
        # Append plaintext
        plaintext += plainblock
        # Update IV
        IV = cipherblock
    return plaintext

def is_ECB( ciphertext ):
    """Looks for repeated blocks in a ciphertext. This is a giveaway that something is encrypted in ECB mode"""
    # Chop up ciphertext into blocks
    num_blocks = len(ciphertext) // BLOCK_SIZE
    blocks = [ ciphertext[BLOCK_SIZE*i:BLOCK_SIZE*(i+1)] for i in range(num_blocks) ]
    # Check if any blocks are repeated
    return len(set(blocks)) != len(blocks)

# Some globals for challenges
from base64 import b64decode
import random
KEY_SIZE = 16
MESSAGE64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
MESSAGE = b64decode(MESSAGE64)
random.seed(1)

def getrandkey(n):
    """Generate a random n-byte key"""
    return bytes([ random.getrandbits(8) for _ in range(n) ])

KEY = getrandkey(KEY_SIZE)
prefixsize = random.randint(10, 20)
PREFIX = bytes([ random.getrandbits(8) for _ in range(prefixsize) ])

# Challenge 12 functions
def oracle12( prefix ):
    """Prefixes MESSAGE with prefix0 and then encrypts it using ECB"""
    plain = prefix + MESSAGE
    return AES_ECB_encrypt( plain, KEY )

# Challenge 13 functions
def profile_for( usermail ):
    if ('&' in usermail or '=' in usermail):
        raise ValueError("Email cannot contain & or = characters")
    USERCOUNT = 10
    profile = "email={0}&UID={1}&role={2}".format(usermail, USERCOUNT, "user")
    return profile

def oracle13( usermail ):
    """Generates a user profile using usermail and encrypts it"""
    random.seed(1)
    key = getrandkey( KEY_SIZE )
    profile = profile_for( usermail )
    return AES_ECB_encrypt( profile.encode(), key )

def kvparse( text ):
    pairs = text.split('&')
    pairs = [ pair.split('=') for pair in pairs ]
    return { pair[0]:pair[1] for pair in pairs }

def decrypt13( encryptedprofile ):
    random.seed(1)
    key = getrandkey( KEY_SIZE )
    profile = AES_ECB_decrypt( encryptedprofile, key )
    profile = profile.decode().strip('\x04')
    return kvparse(profile)

#Challenge 14 functions
def oracle14( textbytes ):
    """Inserts text inbetween PREFIX and MESSAGE then encrypts the whole thing and returns it"""
    plain = PREFIX + textbytes + MESSAGE
    return AES_ECB_encrypt(plain, KEY)