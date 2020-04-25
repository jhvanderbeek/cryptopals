import sys
sys.path.append('/home/daniel/Projects/cryptopals/lib')
from aesp import oracle17, validPadding
from functools import reduce

# We're going to assume we know the blocksize here. In practice you might be 
# able to determine it if you had more than one message just by finding common 
# divisor of the cipher lengths. Or if you had some influence over what is 
# being encrypted you could change the input until the block jumped.
blocksize = 16

def vPadding( stream ):
    """A wrapper for the validPadding function"""
    return validPadding(stream[blocksize:], stream[:blocksize])


cipher, IV = oracle17()

numblocks = len(cipher)//blocksize
stream = IV + cipher
plaintext = b''
# Decrypt each block
for i in range(numblocks):
    # Grab the block that is xored against the block cipher output for this block of cipher
    prevBlocks = stream[:(i+1)*blocksize]
    # Grab the block we want to decrypt
    thisBlock = stream[(i+1)*blocksize:(i+2)*blocksize]
    # Check if this is the last block
    if vPadding(prevBlocks + thisBlock):
        # Find the startpoint by messing with the padding
        lastblock = prevBlocks[-blocksize:]
        j = 0
        messwith = lastblock[:j] + bytes([lastblock[j] ^ 255]) + lastblock[j+1:]
        while vPadding(messwith + thisBlock):
            j += 1
            messwith = lastblock[:j] + bytes([lastblock[j] ^ 255]) + lastblock[j+1:]
        startpoint = blocksize - j + 1
        padblock = prevBlocks[1-startpoint:]
        padblock = bytes([ x^(startpoint)^(startpoint-1) for x in padblock ])
        plainblock = bytes([startpoint - 1]) * (startpoint - 1)
    else:
        startpoint = 1
        padblock = b''
        plainblock = b''
    # We need everything before this block to decrypt properly
    # Decrypt starting at the last byte of the block
    for j in range(startpoint, blocksize + 1):
        k = 0
        while not vPadding(prevBlocks[:-j] + bytes([k]) + padblock + thisBlock):
            k += 1
            if k>=256:
                print("Something has gone terribly wrong!")
                exit()
        # When we have valid padding it means that the output of the block cipher xored with k gives the padding byte
        outputbyte = k^j
        # To get the plainbyte we xor with the original cipher byte
        plainbyte = outputbyte ^ prevBlocks[-j]
        plainblock = bytes([plainbyte]) + plainblock
        padblock = bytes([ (j+1)^x^y for (x,y) in zip(prevBlocks[-j:],plainblock) ])
    plaintext += plainblock

print(plaintext)
