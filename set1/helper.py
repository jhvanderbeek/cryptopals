from math import ceil
from functools import reduce

def hexstrtobytes(hexstr):
    """Converts a string of hex characters into an array of bytes"""
    # First split hexstr up into two character chunks (so each chunk is a byte)
    hexarr = [ int(hexstr[2*i: 2*(i+1)],16) for i in range(ceil(len(hexstr)/2)) ]
    # Convert the hex numbers into bytes
    bytearr = bytes(hexarr)
    return bytearr

def bytestohexstr(bytearr):
    """Converts an array of bytes to a string of hex characters"""
    hexarr = [ "{:02x}".format(i) for i in bytearr ]
    hexstr = reduce( str.__add__, hexarr )
    return hexstr

def xorarrays(bytes1, bytes2):
    """Does an elementwise xor on a bytes object and returns the
    result in a bytes object"""
    n = min( len(bytes1), len(bytes2) )
    result = [ x^y for (x,y) in zip(bytes1, bytes2) ]
    return bytes(result)

def score( translation ):
    """Scores a string according to the frequency of the characters
    it contains"""
    # Make a dictionary to score letters according to frequency
    order = "etaoinshrdluwmfcgypbkvjxqz"
    scorecard = dict( zip(order, range(len(order))) )
    # Score each letter in the translation
    scores = [ scorecard[chr(i).lower()] if chr(i).lower() in scorecard.keys() else 50 for i in translation ]
    # Add up the scores
    finalscore = reduce(int.__add__, scores)
    
    return finalscore
