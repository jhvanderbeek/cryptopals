# Read in encrypted lines
filename = "/home/daniel/Projects/cryptopals/set1/8.txt"
with open(filename) as f:
    lines = f.readlines()

possibilities = []

# Look for lines that have repeated blocks
# This is a giveaway that it uses ECB
for line in lines:
    # Get the bytes represented by the characters
    byteline = bytes.fromhex(line.strip())
    # Chop it up into 16 byte blocks
    blocks = [byteline[ 16*i:16*(i+1) ] for i in range(len(byteline) // 16)]
    # Check if any blocks are repeated
    if ( len(set(blocks)) != len(blocks) ):
        possibilities.append(byteline)

print("{} possibilities found".format(len(possibilities)))

## Try to decrypt using key "YELLOW SUBMARINE"
# Access functions from c library
from ctypes import *
sofilename = "/home/daniel/Projects/cryptopals/set1/aes.so"
aes = CDLL(sofilename)

# Set key
key = create_string_buffer(b"YELLOW SUBMARINE")

# Decrypt the ciphertext one block at a time
for cipherbytes in possibilities:
    plaintext = b''
    plainblock = create_string_buffer(16)
    for i in range(len(cipherbytes) // 16):
        aes.AESdecrypt( cipherbytes[16*i : 16*i+16], key, plainblock )
        plaintext += plainblock.value

print(plaintext) #Sadly doesn't work lol