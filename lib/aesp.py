# Access functions from c library
from ctypes import *
sofilename = "/home/daniel/Projects/cryptopals/lib/aes.so"
aes = CDLL(sofilename)
BLOCK_SIZE = 16

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
    for i in range(len(cipherbytes) // BLOCK_SIZE):
        aes.AESdecrypt( cipherbytes[BLOCK_SIZE*i : BLOCK_SIZE*i+BLOCK_SIZE], key, plainblock )
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

