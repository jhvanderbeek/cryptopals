import sys
sys.path.append('/home/daniel/Projects/cryptopals/lib')
import random
from aesp import oracle14


# The challenge is to determine the text of MESSAGE using only calls to oracle. 
# (We aren't allowed to look at the string EXTRA itself and we don't know the 
# key used to encrypt it)

def determineBlockSize():
    """Determine block size by enrcypting succesively larger plaintexts and seeing when the size of the ciphertext jumps"""
    insert = b''
    cipher = oracle14( insert )
    initialsize = len( cipher )
    # First add prefixes until we get to the start of a jump
    while ( len(cipher) == initialsize ):
        insert += b'A'
        cipher = oracle14( insert )
    # Note how much we need for the first jump
    firstjump = len(insert)
    # Now start counting how many until the next jump
    initialsize = len(cipher)
    blocksize = 0
    while ( len(cipher) == initialsize ):
        insert += b'A'
        blocksize += 1
        cipher = oracle14( insert )
    return blocksize, firstjump

def determineInsertPosition(blocksize):
    """Determines where text is being inserted by detecting repeated blocks"""
    # Make sure there are no repeated blocks to start with
    cipher = oracle14(b'')
    numBlocks = len(cipher) // blocksize
    cipherblocks = [ cipher[i*blocksize:(i+1)*blocksize] for i in range(numBlocks) ]
    if len(cipherblocks) != len(set(cipherblocks)):
        print("Repeat blocks found in unaltered cipher watch out!!!")
    # Start with two blocks worth of As
    insert = b'A' * 2 * blocksize
    cipher = oracle14(insert)
    cipherblocks = [ cipher[i*blocksize:(i+1)*blocksize] for i in range(numBlocks) ]
    # If we detect repeated blocks then the As have filled up two full blocks.
    # We must be inserting into the block just before the repeats
    extras = 0
    while len(cipherblocks) == len(set(cipherblocks)):
        insert += b'A'
        extras += 1
        cipher = oracle14(insert)
        cipherblocks = [ cipher[i*blocksize:(i+1)*blocksize] for i in range(numBlocks) ]
    
    # Find the repeated block
    numBlocks = len(cipher) // blocksize
    for i in range(numBlocks-1):
        thisblock = cipher[blocksize*i:blocksize*(i+1)]
        nextblock = cipher[blocksize*(i+1):blocksize*(i+2)]
        if thisblock == nextblock:
            break
    insertIndex = blocksize * i - extras
    return insertIndex

blocksize, firstjump = determineBlockSize()
# Find out where we are inserting
insertPosition = determineInsertPosition(blocksize)
insertBlockNumber = insertPosition // blocksize + 1

# Now we want to insert stuff so that the ith cipher character is on the end of 
# a block
plainblock = b'A'*blocksize
plaintext = b''
if insertPosition % blocksize != 0:
    insertPrefix = b'A'*(blocksize - insertPosition%blocksize)
else:
    insertPrefix = b''
cipher = oracle14(insertPrefix + plainblock)
numBlocks = len(cipher) // blocksize

for block in range(numBlocks - insertBlockNumber - 1):
    # Reset the prefix
    insert = b'A'*blocksize
    # i will count the position in the block
    for i in range( blocksize ):
        # Reduce the insert by one A
        insert = insert[1:]
        # Pop the first byte of plainblock and add the newest plaintext 
        # character
        if (block == 0 and i == 0):
            # In the very first run through there is no plaintext to add
            plainblock = plainblock[1:]
        else:
            plainblock = plainblock[1:] + bytes([plaintext[-1]])
        # Encrypt the text with the insert and chop out the interesting block
        cipher = oracle14( insertPrefix + insert )

        nextByteBlock = cipher[ (insertBlockNumber + block)*blocksize : (insertBlockNumber + block + 1)*blocksize ]
        
        # Determine what the character next to the insert block is
        for j in range(256):
            possiblility = oracle14(insertPrefix + plainblock + bytes([j]))[ insertBlockNumber*blocksize:(insertBlockNumber + 1)*blocksize]
            if possiblility == nextByteBlock:
                plaintext += bytes([j])
                break
        else:
            print("It looks like something went terribly wrong")
            print("Block: {}, i: {}".format(block, i))
        # # Make a lookup table for all the possible next characters
        # lookup = [ oracle14( insertPrefix + plainblock + bytes([j]) )[insertBlockNumber*blocksize:(insertBlockNumber+1)*blocksize] for j in range(256) ]
        # nextByte = lookup.index( nextByteBlock )
        # # Add the decrypted character to the plaintext
        # plaintext += bytes([nextByte])
        
print(plaintext)
