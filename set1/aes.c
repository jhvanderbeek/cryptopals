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

/**
 * Computes the roundkey for a given round.
 * 
 * Uses Rijndael's key schedule to calculate the constant for that round
 * @param round     The round number
 * 
 * @return roundkey The key for that round
 */
Byte roundkey( int round ) {
    /* Round must be at least 1 */
    if ( round < 1 ) {
        return NULL;
    }
    Byte roundkey = 1;
    /* For the first 8 rounds the key is simply shifted*/
    if ( round < 9 ) {
        roundkey <<= (round - 1);
        return roundkey;
    }
    /* For the remaining rounds always shift to the left by one and then, if   
        the highest order bit is set, xor against a constant (0x1b). */
    else {
        roundkey = 0x80;
        for (int i = 9; i <= round; ++i) {
            /* In order to check if the highest bit is set we shift it so that
             only the highest bit is showing, then negate it. If the highest 
             bit is 1 the negative is stored as 0xff, if the highest bit is 
             zero the negative is 0x00. We use this as a mask for the xor 
             constant.*/
            roundkey = ( roundkey << 1 ) ^ ( 0x1b && -(roundkey >> 7) );
        }
        return roundkey;
    }
}
