import sys
import helper

hexstr = sys.argv[1]

bytearr = helper.hexstrtobytes(hexstr)

# Convert the bytes to base64 numbers
from base64 import b64encode
sfbytes = b64encode(bytearr)
print(str(sfbytes)[2:-1])