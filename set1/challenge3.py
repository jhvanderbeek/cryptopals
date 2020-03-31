import sys
import helper as h

usrinput = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

# Read ciphertext in from command line
#ciphertext = h.hexstrtobytes(sys.argv[1])
ciphertext = h.hexstrtobytes(usrinput)
# Make a holder for plaintext trials
possPlain = bytes( len(ciphertext) )
bestPlain = bytes( len(ciphertext) )
# Set bestScore to max possible value
bestScore = 50 * len(ciphertext)

allowableChars = list(range(32, 127))

# Try each key and find which gives the best score
for key in range(256):
    # Decrypt the ciphertext using key
    possPlain = [ key ^ cipher for cipher in ciphertext ]
    # If this contains something that isn't a letter or a space then skip it
    
    readable = [ (char in allowableChars) for char in possPlain ]
    if ( all(readable) and (h.score(possPlain) < bestScore) ):
        bestScore = h.score(possPlain)
        bestPlain = possPlain
        # print(bytes(possPlain), h.score(possPlain))

print(bytes(bestPlain))

