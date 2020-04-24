
def pad(text, n):
    """Adds padding to a string of bytes to make it length n. If the string is longer than n it will return the first n bytes of text"""
    if n > len(text)+256:
        raise ValueError("Cannot exceed 256 bytes of padding!")
    if ( len(text) > n ):
        return text[:n]
    to_add = n - len(text)
    return text + bytes([to_add])*to_add