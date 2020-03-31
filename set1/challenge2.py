import sys
import helper as h

# Take command line arguments as key and plaintext
key = h.hexstrtobytes(sys.argv[1])
plaintext = h.hexstrtobytes(sys.argv[2])

# xor them together to get ciphertext
ciphertext = h.xorarrays(key, plaintext)
print( h.bytestohexstr(ciphertext) )