/**
 * Some code for aes encryption, sticking to 128 bit keys for now
 * 
 * https://www.samiam.org/key-schedule.html
 */
#include <stdlib.h>
#include <assert.h>
#define BITS_PER_BYTE   8
typedef unsigned char Byte;

/**
 * Rotates a single byte to the left by n bits.
 * 
 * Takes a byte 'in' and moves the ith element to the (i-n)th position. Bits to 
 * the left of the nth position roll around to the right.
 * @param in    The array of Bytes
 * @param n     The number of bits to shift (can be negative)
 * 
 * @return out  The rotated byte
 */
Byte rotateByteLeft( Byte in, int n ) {
    Byte out = in;
    n = n % BITS_PER_BYTE;
    out = (in << n) | (in >> (BITS_PER_BYTE - n));
    return out;
}

/**
 * Rotates a single byte to the right by n bits.
 * 
 * Takes a byte 'in' and moves the ith element to the (i+n)th position. Bits to 
 * the left of the nth position roll around to the right.
 * @param in    The array of Bytes
 * @param n     The number of bits to shift (can be negative)
 * 
 * @return out  The rotated byte
 */
Byte rotateByteRight( Byte in, int n ) {
    Byte out = in;
    n = n % BITS_PER_BYTE;
    out = (in >> n) | (in << (BITS_PER_BYTE - n));
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
        return 0x00;
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
            roundkey = ( roundkey << 1 ) ^ ( 0x1b & -(roundkey >> 7) );
        }
        return roundkey;
    }
}

# if defined TEST
int main () {
    /* Testing for rotateByteLeft and rotateByteRight*/
    /* Basic functionality */
    {
        Byte testByte = 0x01;
        assert( rotateByteLeft(testByte, 1) == 0x02 ); 
        assert( rotateByteRight(testByte, 1) == 0x80 );
        testByte = 0x80;
        assert( rotateByteLeft(testByte, 1) == 0x01 );
        assert( rotateByteRight(testByte, 1) == 0x40 );
        testByte = 0xaa;
        assert( rotateByteLeft(testByte, 1) == 0x55 );
        assert( rotateByteRight(testByte, 1) == 0x55 );
        testByte = 0xc5;
        assert( rotateByteLeft(testByte, 3) == 0x2e );
        assert( rotateByteRight(testByte, 3) == 0xb8 );
    }
    /* Unconventional n */
    {
        Byte testByte = 0xc5;
        assert( rotateByteLeft(testByte, 3) == rotateByteRight(testByte, BITS_PER_BYTE - 3) );
        assert( rotateByteLeft(testByte, 2 + BITS_PER_BYTE) == rotateByteLeft(testByte, 2) );
        assert( rotateByteRight(testByte, 2 + BITS_PER_BYTE) == rotateByteRight(testByte, 2) );
    }

    /* Testing for roundkey */
    
}
# endif