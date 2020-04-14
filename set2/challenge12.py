import sys
sys.path.append('/home/daniel/Projects/cryptopals/lib')
import random
from aesp import oracle12


# The challenge is to determine the text of EXTRA only using calls to oracle. 
# (We aren't allowed to look at the string EXTRA itself and we don't know the 
# key used to encrypt it)

# Determine block size by enrcypting succesively larger plaintexts and seeing 
# when the size of the ciphertext jumps
prefix = b''
cipher = oracle12( prefix )
initialsize = len( cipher )
# First add prefixes until we get to the start of a jump
while ( len(cipher) == initialsize ):
    prefix += b'A'
    cipher = oracle12( prefix )
# Now start counting how many until the next jump
initialsize = len(cipher)
blocksize = 0
while ( len(cipher) == initialsize ):
    prefix += b'A'
    blocksize += 1
    cipher = oracle12( prefix )

# Now we want to add prefixes so that the ith cipher character is on the end of a block
numBlocks = len(oracle12(b'')) // blocksize
plainblock = b'A'*blocksize
plaintext = b''

for block in range(numBlocks):
    # Reset the prefix
    prefix = b'A'*blocksize
    # i will count the position in the block
    for i in range( blocksize ):
        # Reduce the prefix by one A
        prefix = prefix[1:]
        # Pop the first byte of plainblock and add the newest plaintext 
        # character
        if (block == 0 and i == 0):
            # In the very first run through there is no plaintext to add
            plainblock = plainblock[1:]
        else:
            plainblock = plainblock[1:] + bytes([plaintext[-1]])
        # Make a lookup table for all the possible next characters
        lookup = [ oracle12( plainblock + bytes([j]) )[:blocksize] for j in range(256) ]
        # Encrypt the text with the prefix
        cipher = oracle12( prefix )
        # Find the match in the lookup table
        nextByteBlock = cipher[ block*blocksize : (block+1)*blocksize ]
        nextByte = lookup.index( nextByteBlock )
        # Add the decrypted character to the plaintext
        plaintext += bytes([nextByte])
        
print(plaintext)
