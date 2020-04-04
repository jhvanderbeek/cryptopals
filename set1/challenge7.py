# Access functions from c library
from ctypes import *
sofilename = "/home/daniel/Projects/cryptopals/set1/aes.so"
aes = CDLL(sofilename)

# Set key
key = create_string_buffer(b"YELLOW SUBMARINE")

# Read in ciphertext
cipherfilename = "/home/daniel/Projects/cryptopals/set1/7.txt"
with open(cipherfilename) as f:
    cipher64 = f.read()
# Decode from base64
from base64 import b64decode
cipherbytes = b64decode(cipher64)

# Decrypt the ciphertext one block at a time
plaintext = b''
cipherblock = create_string_buffer(16)
plainblock = create_string_buffer(16)
for i in range(len(cipherbytes) // 16):
    aes.AESdecrypt( cipherbytes[16*i : 16*i+16], key, plainblock )
    plaintext += plainblock.value

print(plaintext)