# Make a list of non-printable characters
nonprintable = list(range(32))
nonprintable.remove(9)
nonprintable.remove(10)
nonprintable.remove(13)

nonprintable = bytes(nonprintable)

def stripPadding( text ):
    """Returns the text minus any \x04 padding at the end of the string"""
    while text[-1] in nonprintable:
        if text[-1] == 4:
            text = text[:-1]
        else:
            raise ValueError("Bad padding!")
    return text
    
trial = b"ICE ICE BABY\x04\x04\x04\x04"
trial = stripPadding(trial)
assert( trial == b"ICE ICE BABY")
print("Success!")
trial = b"ICE ICE BABY\x05\x05\x05\x05"
try:
    trial = stripPadding(trial)
    print("Test 2 failed")
except ValueError:
    print("Success!")
trial = b"ICE ICE BABY\x01\x02\x03\x04"
try:
    trial = stripPadding(trial)
    print("Test 2 failed")
except ValueError:
    print("Success!")