import sys
sys.path.append('/home/daniel/Projects/cryptopals/lib')
import random
import aesp as aes
KEY_SIZE = 16

def getrandkey(n):
    """Generate a random n-byte key"""
    return bytes([ random.getrandbits(8) for _ in range(n) ])

def encryptionoracle(plaintext):
    """Appends and prepends 5-10 random bytes to plaintext then encrypts with
    either ECB or CBC using a random key. 
    The choice of encryption mode is made randomly."""
    # Generate a random key
    key = getrandkey(KEY_SIZE)
    # print("Encrypting with key", key)
    # Prepend plaintext with random bytes
    n = random.randint(5, 10)
    fluff = bytes([ random.getrandbits(8) for _ in range(n) ])
    # print( "Adding {} bytes of fluff to start: {}".format(n, fluff) )
    plaintext = fluff + plaintext
    # Append plaintext with random bytes
    n = random.randint(5, 10)
    fluff = bytes([ random.getrandbits(8) for _ in range(n) ])
    # print( "Adding {} bytes of fluff to end:   {}".format(n, fluff) )
    plaintext = plaintext + fluff
    # Randomly choose whether to encrypt with ECB or CBC
    # print("Encrypting:", plaintext, len(plaintext))
    if (random.choice([0,1]) == 0):
        mode = 'ECB'
        # print("In mode", mode)
        cipher = aes.AES_ECB_encrypt( plaintext, key )
    else:
        mode = 'CBC'
        # print("In mode", mode)
        # Generate a random IV
        IV = getrandkey(KEY_SIZE)
        # print("With IV: {}".format(IV))
        cipher = aes.AES_CBC_encrypt( plaintext, key, IV )

    # print( "Result:", cipher, len(cipher))
    return cipher, mode

plain = b"YELLOW SUBMARINE"*5
# Encrypt a bunch of different ways
ciphers = [ encryptionoracle(plain) for _ in range(10) ]
# Try to detect those that were encrypted in ECB
for ciphertext, mode in ciphers:
    detected_mode = 'ECB' if aes.is_ECB(ciphertext) else 'CBC'
    if (detected_mode == mode):
        print("Successfully detected {}!".format(mode))
    else:
        print("Detection failed :(")