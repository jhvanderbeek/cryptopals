/*
 * Some code for aes encryption, sticking to 128 bit keys for now
 * 
 * https://www.samiam.org/key-schedule.html
 */
#include <stdlib.h>
typedef unsigned char Byte;

/**
 * Rotates an array of Bytes of length n to the left.
 * 
 * Takes an array of bytes 'in' of length n and moves the ith element to the
 * (i-1)th position. The 0th element is moved to the end of the array.
 * @param in    The array of Bytes
 * @param n     The size of the array
 * 
 * @return out  The rotated array
 */
Byte *rotateBytesLeft( Byte *in, size_t n ) {
    Byte *out = malloc( sizeof(Byte) * n );
    out[n] = in[0];
    for (size_t i = 1; i < n; ++i) {
        out[i-1] = in[i];
    }
    return out;
}

/**
 * Rotates an array of Bytes of length n to the right.
 * 
 * Takes an array of bytes 'in' of length n and moves the ith element to the
 * (i+1)th position. The nth element is moved to the start of the array.
 * @param in    The array of Bytes
 * @param n     The size of the array
 * 
 * @return out  The rotated array
 */
Byte *rotateBytesRight( Byte *in, size_t n ) {
    Byte *out = malloc( sizeof(Byte) * n );
    out[0] = in[n];
    for (size_t i = 1; i < n; ++i) {
        out[i] = in[i-1];
    }
    return out;
}

