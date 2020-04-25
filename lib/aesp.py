# Access functions from c library
from ctypes import *
sofilename = "/home/daniel/Projects/cryptopals/lib/aes.so"
aes = CDLL(sofilename)
BLOCK_SIZE = 16

# AES functions
def pad( text ):
    """Adds padding to a string of bytes to make it a multiple of BLOCK_SIZE."""
    r = len(text)%BLOCK_SIZE
    to_add = BLOCK_SIZE - r
    return text + bytes([to_add])*(to_add)

def padding_is_valid( text ):
    """Returns the text minus padding at the end of the string"""
    count = int(text[-1])
    check = text[-count:]
    check = [ int(padbyte) == count for padbyte in check ]
    return all(check)

def AES_ECB_encrypt( plaintext, key ):
    """Encrypts the plaintext using a 128 bit key in ECB mode. Plaintext is 
    automatically padded as necessary."""
    # Make a copy of plaintext so it doesn't get changed
    plainbytes = bytes([ x for x in plaintext ])
    # Pad the plaintext to a multiple of BLOCK_SIZE
    plainbytes = pad(plainbytes)

    ciphertext= b''
    cipherblock = create_string_buffer(BLOCK_SIZE)
    for i in range( len(plainbytes) // BLOCK_SIZE ):
        aes.AESencrypt( plainbytes[BLOCK_SIZE*i : BLOCK_SIZE*i+BLOCK_SIZE], key, cipherblock )
        ciphertext += bytes(cipherblock)
        # Note! Don't use cipherblock.value! This will incorrectly terminate if 
        # there is a \00
    return ciphertext

def AES_ECB_decrypt( ciphertext, key ):
    """Decrypts the ciphertext using a 128 bit key in ECB mode."""
    # Decrypt the ciphertext one block at a time
    plaintext = b''
    plainblock = create_string_buffer(BLOCK_SIZE)
    cipherblock = create_string_buffer(BLOCK_SIZE)
    for i in range(len(ciphertext) // BLOCK_SIZE):
        cipherblock = ciphertext[BLOCK_SIZE*i : BLOCK_SIZE*i+BLOCK_SIZE]
        aes.AESdecrypt( cipherblock, key, plainblock )
        plaintext += bytes(plainblock)
    return plaintext

def AES_CBC_encrypt( plaintext, key, IV ):
    """Encrypts the plaintext using a 128 bit key and initialisation 
    vector. Plaintext is automatically padded as necessary."""
    # Make a copy of plaintext so it doesn't get changed
    plainbytes = bytes([ x for x in plaintext ])
    # Pad the plaintext to a multiple of BLOCK_SIZE
    plainbytes = pad(plainbytes)

    ciphertext= b''
    cipherblock = create_string_buffer(BLOCK_SIZE)
    for i in range( len(plainbytes) // BLOCK_SIZE ):
        plainblock = plainbytes[BLOCK_SIZE*i : BLOCK_SIZE*i+BLOCK_SIZE]
        # xor plaintext and IV
        plainblock = bytes([ a^b for (a,b) in zip(plainblock, IV) ])
        # Encrypt with key
        aes.AESencrypt( plainblock, key, cipherblock )
        # Update IV
        IV = bytes(cipherblock)
        # Append ciphertext
        ciphertext += bytes(cipherblock)
        # Note! Don't use cipherblock.value! This will incorrectly terminate if 
        # there is a \00
    return ciphertext

def AES_CBC_decrypt( ciphertext, key, IV ):
    """Decrypts the ciphertext using a 128 bit key and initialisation vector."""
    plaintext = b''
    cipherblock = create_string_buffer(BLOCK_SIZE)
    preplainblock = create_string_buffer(BLOCK_SIZE)
    plainblock = [0]*16
    for i in range(len(ciphertext) // BLOCK_SIZE):
        cipherblock = ciphertext[BLOCK_SIZE*i : BLOCK_SIZE*i+BLOCK_SIZE]
        # Decrypt block using key
        aes.AESdecrypt( cipherblock, key, preplainblock )
        # xor with IV to get plaintext
        plainblock = bytes([ ord(a)^b for (a,b) in zip(preplainblock, IV) ])
        # Append plaintext
        plaintext += plainblock
        # Update IV
        IV = cipherblock
    return plaintext

def is_ECB( ciphertext ):
    """Looks for repeated blocks in a ciphertext. This is a giveaway that something is encrypted in ECB mode"""
    # Chop up ciphertext into blocks
    num_blocks = len(ciphertext) // BLOCK_SIZE
    blocks = [ ciphertext[BLOCK_SIZE*i:BLOCK_SIZE*(i+1)] for i in range(num_blocks) ]
    # Check if any blocks are repeated
    return len(set(blocks)) != len(blocks)

# Some globals for challenges
from base64 import b64decode
import random
KEY_SIZE = 16
MESSAGE64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
MESSAGE = b64decode(MESSAGE64)
random.seed(1)

def getrandkey(n):
    """Generate a random n-byte key"""
    return bytes([ random.getrandbits(8) for _ in range(n) ])

KEY = getrandkey(KEY_SIZE)
prefixsize = random.randint(10, 20)
PREFIX = bytes([ random.getrandbits(8) for _ in range(prefixsize) ])

# Challenge 12 functions
def oracle12( prefix ):
    """Prefixes MESSAGE with prefix0 and then encrypts it using ECB"""
    plain = prefix + MESSAGE
    return AES_ECB_encrypt( plain, KEY )

# Challenge 13 functions
def profile_for( usermail ):
    if ('&' in usermail or '=' in usermail):
        raise ValueError("Email cannot contain & or = characters")
    USERCOUNT = 10
    profile = "email={0}&UID={1}&role={2}".format(usermail, USERCOUNT, "user")
    return profile

def oracle13( usermail ):
    """Generates a user profile using usermail and encrypts it"""
    profile = profile_for( usermail )
    return AES_ECB_encrypt( profile.encode(), key )

def kvparse( text ):
    pairs = text.split('&')
    pairs = [ pair.split('=') for pair in pairs ]
    return { pair[0]:pair[1] for pair in pairs }

def decrypt13( encryptedprofile ):
    random.seed(1)
    key = getrandkey( KEY_SIZE )
    profile = AES_ECB_decrypt( encryptedprofile, key )
    profile = profile.decode().strip('\x04')
    return kvparse(profile)

# Challenge 14 functions
def oracle14( textbytes ):
    """Inserts text inbetween PREFIX and MESSAGE then encrypts the whole thing and returns it"""
    plain = PREFIX + textbytes + MESSAGE
    return AES_ECB_encrypt(plain, KEY)

IV = getrandkey(KEY_SIZE)

# Challenge 16 functions
import re
def oracle16( userdata ):
    """Inserts userdata between the prefix and suffix strings and then 
    encrypts"""
    # Don't allow the string to end in an escape character ('\\'=92 in ascii)
    if len(userdata) > 0 and userdata[-1] == 92:
        raise ValueError("userdata cannot end in \\")
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
    # First add escape characters to all ; and = in userdata
    userdata = userdata.split(b';')
    userdata = b'\;'.join(userdata)
    userdata = userdata.split(b'=')
    userdata = b'\='.join(userdata)
    # print(prefix + userdata + suffix)
    return AES_CBC_encrypt( prefix + userdata + suffix, KEY, IV)

def isadmin( encdata ):
    """Decrypts the string encdata and looks for the string ';admin=true;'"""
    data = str(AES_CBC_decrypt( encdata, KEY, IV ))
    data = re.split(r'(?<!\\);', data)
    data = [ re.split( r'(?<!\\)=', x ) for x in data ]
    data = dict(data)
    if "admin" in data and data["admin"] == "true":
        return True
    else:
        return False

def determineBlocksize( blockcipher ):
    """Expects a function that takes in text and ecrypts it possibly in addition to some text before and after using a block cipher. This function will determine the size of the blocks by enrcypting succesively larger plaintexts and seeing when the size of the ciphertext jumps"""
    insert = b''
    cipher = blockcipher( insert )
    initialsize = len( cipher )
    # First add prefixes until we get to the start of a jump
    while ( len(cipher) == initialsize ):
        insert += b'A'
        cipher = blockcipher( insert )
    # Now start counting how many until the next jump
    initialsize = len(cipher)
    blocksize = 0
    while ( len(cipher) == initialsize ):
        insert += b'A'
        blocksize += 1
        cipher = blockcipher( insert )
    return blocksize

def determineInsertPosition( blockcipher, blocksize ):
    """Determines where text is being inserted by detecting changes in the cipher"""
    # Start by inserting text of length blocksize
    insert = bytearray( blocksize + 1 )
    fixedcipher = blockcipher( insert )
    
    # Change the insert at the start
    insert[0] = 1
    cipher = blockcipher( insert )
    numBlocks = len(cipher) // blocksize

    # Find where the blocks change
    fixedblocks = [ fixedcipher[i*blocksize:(i+1)*blocksize] for i in range(numBlocks) ]
    cipherblocks = [ cipher[i*blocksize:(i+1)*blocksize] for i in range(numBlocks) ]
    
    diff = [ a != b for a,b in zip(fixedblocks, cipherblocks) ]
    startblock = diff.index(True)
    diffblock = startblock
    count = 0
    # Change successive letters in insert until a different block changes
    while diffblock == startblock:
        count += 1
        insert = bytearray(blocksize + 1)
        insert[count] = 1

        cipher = blockcipher( insert )
        cipherblocks = [ cipher[i*blocksize:(i+1)*blocksize] for i in range(numBlocks) ]
        
        diff = [ a != b for a,b in zip(fixedblocks, cipherblocks) ]
        diffblock = diff.index(True)

    assert(count < blocksize + 1)
    # If insert starts at the start of a block the count will go over
    if count == blocksize:
        return blocksize * startblock

    return blocksize*(startblock + 1) - count

# Challenge 17 functions
KEY17 = KEY
IV17 = IV
def oracle17():
    """Chooses a random plaintext from 17.txt, encrypts it under CBC, then returns the encrypted text and the IV"""
    with open("/home/daniel/Projects/cryptopals/set3/17.txt", 'r') as f:
        lines = f.readlines()
        line = b64decode(random.choice(lines))
    return AES_CBC_encrypt(line, KEY17, IV17), IV17

def validPadding( cipher, iv ):
    """Decrypts cipher using KEY17 and iv then check the padding and returns True or False based on the validity of the padding"""
    plain = AES_CBC_decrypt(cipher, KEY17, iv)
    return padding_is_valid(plain)