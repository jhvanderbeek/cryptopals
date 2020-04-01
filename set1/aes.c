/**
 * Some code for aes encryption, sticking to 128 bit keys for now
 * 
 * https://www.samiam.org/key-schedule.html
 */
#include <stdlib.h>
typedef unsigned char Byte;

/**
 * Rotates an array of Bytes of length n to the left by t bits.
 * 
 * Takes an array of bytes 'in' of length n and moves the ith element to the
 * (i-t)th position. Bits to the left of the tth position roll around to the 
 * right.
 * @param in    The array of Bytes
 * @param n     The size of the array
 * @param t     The number of bits to shift
 * 
 * @return out  The rotated array
 */
Byte *rotateBytesLeft( Byte *in, size_t n, size_t t) {
    Byte *out = malloc( sizeof(Byte) * n );
    out = (*in << t) || (*in >> (n-t));
    return out;
}

/**
 * Rotates an array of Bytes of length n to the right by t bits.
 * 
 * Takes an array of bytes 'in' of length n and moves the ith element to the
 * (i+t)th position. Bits to the right of the (n-t)th position roll around to
 * the left.
 * @param in    The array of Bytes
 * @param n     The size of the array
 * @param t     The number of bits to shift
 * 
 * @return out  The rotated array
 */
Byte *rotateBytesRight( Byte *in, size_t n, size_t t ) {
    Byte *out = malloc( sizeof(Byte) * n );
    out = (*in >> t) || (*in << (n-t));
    return out;
}

