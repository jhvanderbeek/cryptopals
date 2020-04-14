# Access functions from c library
from ctypes import *
sofilename = "/home/daniel/Projects/cryptopals/set1/aes.so"
aes = CDLL(sofilename)

# Set key
key = create_string_buffer(b"YELLOW SUBMARINE")

# Read in ciphertext
cipherfilename = "/home/daniel/Projects/cryptopals/set2/10.txt"
with open(cipherfilename) as f:
    cipher64 = f.read()
# Decode from base64
from base64 import b64decode
cipherbytes = b64decode(cipher64)

# Decrypt the ciphertext in CBC mode
BLOCK_LENGTH = 16
plaintext = b''
IV = bytes(b'\x00' * BLOCK_LENGTH)
cipherblock = create_string_buffer(BLOCK_LENGTH)
preplainblock = create_string_buffer(BLOCK_LENGTH)
plainblock = [0]*16
for i in range(len(cipherbytes) // BLOCK_LENGTH):
    cipherblock = cipherbytes[BLOCK_LENGTH*i : BLOCK_LENGTH*i+BLOCK_LENGTH]
    # Decrypt block using key
    aes.AESdecrypt( cipherblock, key, preplainblock )
    # xor with IV to get plaintext
    for i in range(BLOCK_LENGTH):
        plainblock[i] = ord(preplainblock[i]) ^ IV[i]
    # Append plaintext
    plaintext += bytes(plainblock)
    # Update IV
    IV = cipherblock

print(plaintext)