import sys

hexstr = sys.argv[1]

#a = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

# First split hexstr up into two character chunks (so each chunk is a byte)
from math import ceil
hexarr = [ int(hexstr[2*i: 2*(i+1)],16) for i in range(ceil(len(hexstr)/2)) ]
# Convert the hex numbers into bytes
bytearr = bytes(hexarr)
# Convert the bytes to base64 numbers
from base64 import b64encode
sfbytes = b64encode(bytearr)
print(str(sfbytes)[2:-1])