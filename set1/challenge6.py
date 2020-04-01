import binascii
from functools import reduce
import helper

# Read in 6.txt
filename = "/home/daniel/Projects/cryptopals/set1/6.txt"
with open(filename) as f:
    fulltext = f.read()

# 6.txt contains base64 encoded data so we want to turn it in to bytes
lines = fulltext.split('\n')
binlines = [ binascii.a2b_base64(line) for line in lines ]
bintext = reduce(bytes.__add__, binlines)

# Now all the data is stored as a binary object in bintext
# To find the most likely keysize we compare blocks of size
# keysize and compute the normalised hamming distance

distforkey = dict()
for keysize in range(2, 41):
    distances = [0]*7 # Checking seven pairs just coz
    for i in range(0, 14, 2):
        block1 = bintext[keysize * i: keysize * (i+1)]
        block2 = bintext[keysize * (i+1): keysize * (i+2)]
        distances[i//2] = helper.hammingdistance( block1, block2 ) / keysize
    distforkey[keysize] = sum(distances)
# Now sort the keysizes according to their cumulative normalised 
# hamming distances and find the most likely keysize
sorteddists = sorted(distforkey.items(), key=lambda item: item[1])
bestkeysize = sorteddists[0][0]

# Chop up bintext into chunks of size key size and make keysize blocks, 
# the ith block containing the ith byte of each chunk 

blocks = [] 
for i in range(bestkeysize):
    blocks.append(list()) 

for i in range( len(bintext) // bestkeysize ):
    # We want to put the jth byte of chunk i in block j
    chunk = bintext[ i * bestkeysize: (i+1) * bestkeysize ]
    for j in range( bestkeysize ):
        blocks[j].append(chunk[j])

# Now blocks[i] contains a list of bytes that have all hopefully 
# been xor'ed with the same character so just use code from challenge 3
key = []
for block in blocks:
    thiskey, translation, score = helper.findbestkeyfor(block)
    key.append(thiskey)
key = bytes(key)

plaintext = helper.repeatingkeyxor( bintext, key )

plaintext = bytes(plaintext)
print(key)
print(plaintext)
    