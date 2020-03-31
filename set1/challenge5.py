import helper

message = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

key = b"ICE"

cipher = helper.repeatingkeyxor(message, key)
print(helper.bytestohexstr(cipher))