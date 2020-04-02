/**
 * Some code for aes encryption, sticking to 128 bit keys for now
 * 
 * https://www.samiam.org/key-schedule.html
 */
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#define BITS_PER_BYTE   8
#define BYTES_PER_WORD  4  
// #define TEST
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
 * Rotates a word of bytes to the left by one byte.
 * 
 * Moves bytes of a word to the left by one. The 0th byte is moved to the end 
 * of the word. Does so in place.
 * @param in    The word to be rotated
 */
void rotateWordLeft(Byte *in) {
        Byte tmp;
        tmp = in[0];
        for(size_t i = 0; i < BYTES_PER_WORD - 1; ++i) 
                in[i] = in[i + 1];
        in[BYTES_PER_WORD - 1] = tmp;
        return;
}

/**
 * Rotates a word of bytes to the right by one byte.
 * 
 * Moves bytes of a word to the right by one. The last byte is moved to the
 * beginning of the word. Does so in place.
 * @param in    The word to be rotated
 */
void rotateWordRight(Byte *in) {
        Byte tmp;
        tmp = in[BYTES_PER_WORD - 1];
        for(size_t i = BYTES_PER_WORD - 1; i > 0; --i) 
                in[i] = in[i - 1];
        in[0] = tmp;
        return;
}

/**
 * Computes the roundkey for a given round.
 * 
 * Uses Rijndael's key schedule to calculate the constant for that round. 
 * This is equivalent to multiplying by x in the field 
 * \mathbb{F}_2[x] / (x^8 + x^4 + x^3 + x + 1)
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
    printf("rotateByteLeft and rotateByteRight passed testing!\n");

    /* Testing for rotateWordLeft and rotateWordRight*/
    {
        Byte word[] = {0x01, 0x02, 0x03, 0x04};
        Byte testword1[] = {0x02, 0x03, 0x04, 0x01};
        Byte testword2[] = {0x04, 0x01, 0x02, 0x03};
        rotateWordLeft(word);
        for (size_t i = 0; i < 4; ++i) {
            assert(word[i] == testword1[i]);
        }
        rotateWordRight(word);
        rotateWordRight(word);
        for (size_t i = 0; i < 4; ++i) {
            assert(word[i] == testword2[i]);
        }
    }
    printf("rotateWordLeft and rotateWordRight passed testing!\n");

    /* Testing for roundkey */
    {
        Byte testvectors[] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a};
        for (size_t i; i < 16; ++i) {
            assert( roundkey(i) == testvectors[i] );
        }
    }
    printf("roundkey passed testing!\n");
}
# endif