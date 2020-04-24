def stripPadding( text ):
    """Returns the text minus padding at the end of the string"""
    count = int(text[-1])
    check = text[-count:]
    check = [ int(padbyte) == count for padbyte in check ]
    if all(check):
        return text[:-count]
    else:
        raise ValueError("Invalid padding!")
    
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