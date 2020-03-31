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

# Scrabble scoring
scorecard = {'a':1, 'b':3, 'c':3, 'd':2, 'e':1, 'f':4, 'g':2, 'h':4, 'i':1, j:'8', 'k':5, 'l':1, 'm':3, 'n':1, 'o':1, 'p':3, 'q':10, 'r':1, 's':1, 't':1, 'u':1, 'v':4, 'w':4, 'x':8, 'y':4, 'z':10}

# Make a dictionary to score letters according to frequency
order = "etaoinshrdluwmfcgypbkvjxqz"
scorecard = dict( zip(order, range(len(order))) )

def score( translation ):
    """Scores a string according to the frequency of the characters
    it contains"""
    
    # Score each letter in the translation
    scores = [ scorecard[chr(i).lower()] if chr(i).lower() in scorecard.keys() else 50 for i in translation ]
    # Add up the scores
    finalscore = reduce(int.__add__, scores)
    
    return finalscore

def isreadable( bytearr ):
    """Determines if the bytes in a byte array represent readable ascii characters"""
    readableChars = list(range(32, 127))
    return all( [(char in readableChars) for char in bytearr] )

def singlecharxor( text, key ):
    """xors each character in text with key and returns the result"""
    # text should be a byte array and key a byte
    return [ key ^ character for character in text ]

def repeatingkeyxor( text, key):
    """Cycles through the characters in key and xors them with the
    characters in text"""
    result = [None] * len(text)
    n = len(key)
    for i in range(len(text)):
        result[i] = text[i] ^ key[i % n]
    return result