from math import ceil
def hexstrtobytes(hexstr):
    """Converts a string of hex characters into an array of bytes"""
    # First split hexstr up into two character chunks (so each chunk is a byte)
    hexarr = [ int(hexstr[2*i: 2*(i+1)],16) for i in range(ceil(len(hexstr)/2)) ]
    # Convert the hex numbers into bytes
    bytearr = bytes(hexarr)
    return bytearr