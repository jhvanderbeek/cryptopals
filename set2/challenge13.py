import sys
sys.path.append('/home/daniel/Projects/cryptopals/lib')
from aesp import oracle13, decrypt13

def plainpad( text, blocksize ):
    """Adds padding to a regular string to make it a multiple of blocksize"""
    r = len(text)%blocksize
    to_add = blocksize - r if r != 0 else 0
    return text + '\x04'*(to_add)

# The exercise here is to make a profile whose role is set to admin using only 
# calls to oracle 13 and decrypt13. I think we just want to provide a string 
# that decrypts to a profile with role equals admin

#### First determine the block size
email = ""
cipher = oracle13(email)
initialsize = len( cipher )
# Add letters to email until we get to the start of a jump
while ( len(cipher) == initialsize ):
    email += "A"
    cipher = oracle13( email )
# Now start counting how many until the next jump
initialsize = len(cipher)
blocksize = 0
while ( len(cipher) == initialsize ):
    email += 'A'
    blocksize += 1
    cipher = oracle13( email )

### Determine what "admin" and "user" (padded to blocksize) encrypt to
email += plainpad("admin", blocksize)
email += plainpad("user", blocksize)

cipher = oracle13(email)
# First two blocks are taken up by "email=AAA..A"
# Third block is "admin\x04\x04..\x04"
# Fourth block is "admin\x04\x04..\x04"
adminEnc = cipher[2*blocksize: 3*blocksize]
userEnc = cipher[3*blocksize: 4*blocksize]

# Make email larger until the word user hangs off at the start of a block
email = ''
cipher = oracle13(email)
while (cipher[-blocksize:] != userEnc):
    email += 'A'
    cipher = oracle13(email)

### Now swap out user for admin
admincipher = cipher[:-blocksize] + adminEnc
print("Using the secret key ")
print(admincipher)
print("decrypts to:")
print(decrypt13(admincipher))