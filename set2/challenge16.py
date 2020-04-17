import sys
sys.path.append('/home/daniel/Projects/cryptopals/lib')
from aesp import oracle16, isadmin, determineBlocksize, determineInsertPosition
from math import ceil

# Determine size of blocks
blocksize = determineBlocksize(oracle16)

# Determine where data is being inserted
insertPosition = determineInsertPosition( oracle16, blocksize )

# Craft data that will have a two consecutive blocks of encrypted user 
# inputed data
fillsize = blocksize - (insertPosition % blocksize) if insertPosition % blocksize > 0 else 0
fillblock = bytes( fillsize ) 
data = fillblock + bytes(2*blocksize)

# Encrypt the data
encData = oracle16(data)
# print(encData)
# Change the first of the two consecutive blocks so that the second will decrypt to "...;admin=true;"
specialblock = ceil( insertPosition / blocksize )
numBlocks = len(encData) // blocksize
encBlocks = [ encData[i*blocksize:(i+1)*blocksize] for i in range(numBlocks) ]
# Sometimes need to add nonsense at the start to make sure it doesn't encrypt to something with an unescaped ; or =
secretsauce = b'1;admin=true'
secretsauce = bytes(blocksize - len(secretsauce)) + secretsauce
# xor secretsauce with the specialblock
secretsauce = [ a^b for a,b in zip(secretsauce, encBlocks[specialblock])]
secretsauce = bytes(secretsauce)
alteredBlocks = encBlocks
alteredBlocks[specialblock] = secretsauce
alteredData = b''.join(encBlocks)
# Decrypt the altered data and check it 
if isadmin(alteredData):
    print("Successfully gained admin priveleges!!")
else:
    print("Unsuccessful")