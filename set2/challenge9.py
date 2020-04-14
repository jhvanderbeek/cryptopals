
def pad(text, n):
    """Adds padding to a string of bytes to make it length n. If the string is longer than n it will return the first n bytes of text"""
    if ( len(text) > n ):
        return text[:n]
    return text + b'\x04'*(n - len(text))