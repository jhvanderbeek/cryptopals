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
#define BITS_PER_KEY    128
#define BYTES_PER_KEY   ((BITS_PER_KEY) / (BITS_PER_BYTE))
#define WORDS_PER_KEY   ((BYTES_PER_KEY) / (BYTES_PER_WORD))
#define ROUND_KEYS      10

// #define TEST
// #define VERBOSE
// #define VVERBOSE
/*
Defining TEST will run the test script in main.
Defining VERBOSE will cause functions to print their output and AESencrypt to document steps as it encrypts.
Defining VVERBOSE causes all functions to print input as well and possibly some other things.
*/

typedef unsigned char Byte;

//////////////Key Scheduling///////////////
Byte sbox[] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

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
 * @param out   A buffer to hold the rotated word
 */
void rotateWordLeft(Byte *in, Byte *out) {
        out[BYTES_PER_WORD - 1] = in[0];
        for(size_t i = 0; i < BYTES_PER_WORD - 1; ++i) 
                out[i] = in[i + 1];
        return;
}

void rotateWordLeftInPlace(Byte *word) {
    Byte tmp = word[0];
    for(size_t i = 0; i < BYTES_PER_WORD - 1; ++i) 
        word[i] = word[i + 1];
    word[BYTES_PER_WORD - 1] = tmp;
    return;
}

/**
 * Rotates a word of bytes to the right by one byte.
 * 
 * Moves bytes of a word to the right by one. The last byte is moved to the
 * beginning of the word. Does so in place.
 * @param in    The word to be rotated
 * @param out   A buffer to hold the rotated word
 */
void rotateWordRight(Byte *in, Byte *out) {
        out[0] = in[BYTES_PER_WORD - 1];
        for(size_t i = BYTES_PER_WORD - 1; i > 0; --i) 
                out[i] = in[i - 1];
        return;
}

/**
 * Computes the roundconstant for a given round.
 * 
 * Uses Rijndael's key schedule to calculate the constant for that round. 
 * This is equivalent to multiplying by x in the field 
 * \mathbb{F}_2[x] / (x^8 + x^4 + x^3 + x + 1)
 * @param round     The round number
 * 
 * @return roundconstant The key for that round
 */
Byte roundconstant( int round ) {
    /* Round must be at least 1 */
    if ( round < 1 ) {
        return 0x00;
    }
    Byte roundconstant = 1;
    /* For the first 8 rounds the key is simply shifted*/
    if ( round < 9 ) {
        roundconstant <<= (round - 1);
        return roundconstant;
    }
    /* For the remaining rounds always shift to the left by one and then, if   
        the highest order bit is set, xor against a constant (0x1b). */
    else {
        roundconstant = 0x80;
        for (int i = 9; i <= round; ++i) {
            /* In order to check if the highest bit is set we shift it so that
             only the highest bit is showing, then negate it. If the highest 
             bit is 1 the negative is stored as 0xff, if the highest bit is 
             zero the negative is 0x00. We use this as a mask for the xor 
             constant.*/
            roundconstant = ( roundconstant << 1 ) ^ ( 0x1b & -(roundconstant >> 7) );
        }
        return roundconstant;
    }
}

/**
 * Substitutes the bytes in word using the sbox lookup table. (in place)
 * 
 * The sbox substitution of a particular byte is derived by finding the 
 * multiplicative inverse of that element in Rijndael's Galois field, then 
 * rotating to the left by one bit, and then xoring with the original byte. 
 * That process is repeated a total of four times then finally xored with the 
 * value 0x93. The final result is the substitution.
 * 
 * @param word          The word to be substituted
 * @param subbedWord    A buffer to hold the result
 */
void sboxSub( Byte *word, Byte *subbedWord ) {
    for (size_t i = 0; i < BYTES_PER_WORD; ++i) {
        subbedWord[i] = sbox[word[i]];
    }
    return;
}

/**
 * Generates 10 keys to be used in AES-128 encryption.
 * 
 * @param initialKey    A pointer to a 128-bit key
 * @param keySchdule    A buffer to hold an array of 11 128-bit keys, the first 
 * one being initialKey and the others generated using the AES key schedule
 */
void generateKeySchedule( Byte *initialKey, Byte **keySchedule ) {
    /* Copy initialKey into the first slot of keySchedule */
    for (size_t i = 0; i < BYTES_PER_KEY; ++i) {
        keySchedule[0][i] = initialKey[i];
    }

    /* Fill in the rest of the keys one at a time */
    for (size_t i = 1; i <= ROUND_KEYS; ++i) {
        /* The first step to building the new key is to rotate and sbox the 
        last word of the previous key and store it in the first word */
        Byte *ptrToLastWord = keySchedule[i-1] + (WORDS_PER_KEY-1) * BYTES_PER_WORD;
        rotateWordLeft( ptrToLastWord, keySchedule[i]);
        sboxSub(keySchedule[i], keySchedule[i]);
        /* Then we xor with the first word of the previous key */
        for (size_t j = 0; j < BYTES_PER_WORD; ++j) {
            keySchedule[i][j] ^= keySchedule[i-1][j];
        }
        /* Finally xor the very first byte with the round constant */
        keySchedule[i][0] ^= roundconstant(i);

        /* The rest of the words in this key are built from the previous word xored with the corresponding word of the previous key */
        for (size_t j = 1; j < WORDS_PER_KEY; ++j) {
            Byte *thisWord = keySchedule[i] + j*BYTES_PER_WORD;
            Byte *lastWord = keySchedule[i] + (j-1)*BYTES_PER_WORD;
            Byte *lastKey = keySchedule[i-1] + j*BYTES_PER_WORD;

            for (size_t k = 0; k < BYTES_PER_WORD; ++k) {
                thisWord[k] = lastWord[k] ^ lastKey[k];
            } 
        }
    }
    return;
}

////////////// Encrypting //////////////////
#define BLOCK_SIZE_BITS 128
#define BLOCK_SIZE      16      /* Block size in bytes */
#define COLUMNS         4
#define ROWS            4

/* the number of chars need to represent a word in hex */
#define WORDLEN         (2 * (BYTES_PER_WORD) + 1) 
#define BLOCK_STR_LEN   ((WORDLEN) * 4) /* four words in a block */

// Watch those brackets on the #defines for the love of god
// printf("BLOCK_STR_LEN evaluates to: %i\n", BLOCK_STR_LEN);
// printf("WORDLEN is: %i\n", WORDLEN);

/**
 * Prints a 128-bit block into a string
 * 
 * @param in        the 128-bit block to print
 * @param string    a buffer to hold the resulting string
 */
void prettyPrint( Byte *in, char *string ) {
    /* Two characters for each byte plus 1 space delimiter for each gap between 
    words plus null byte */ 
    /* Use two characters for each byte in a word plus a space at the end */

    for (size_t word = 0; word < WORDS_PER_KEY; ++word) {
        /* Add each byte of the word */ 
        for (size_t b = 0; b < BYTES_PER_WORD; ++b) 
            sprintf( string + word*WORDLEN + 2*b, "%02x", in[word*BYTES_PER_WORD + b] );
        /* Add a space at the end */
        string[ (word+1)*WORDLEN - 1 ] = ' ';
    }
    string[ WORDS_PER_KEY*WORDLEN - 1 ] = '\0';
    return;
}

/**
 * Substitutes all bytes in a 128-bit block using sbox.
 * 
 * @param in    The 128-bit block to be substituted
 */
void subBytes( Byte *in ) {
    #if defined VERBOSE
        char instring[BLOCK_STR_LEN];
    #if defined VVERBOSE
        prettyPrint(in, instring);
        printf( "subBytes block in  %s\n", instring );
    #endif
    #endif

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        in[i] = sbox[in[i]];
    }

    #if defined VERBOSE
        prettyPrint(in, instring);
        printf( "Byte substitution:  %s\n", instring );
    #endif
    return;
}

/**
 * Jumbles a 128-bit block according to the shift rows step of AES.
 * 
 * The 128-bit block of data is arranged in a 4x4 matrix of bytes so that the 
 * first four byts of the block represent the first column of the matrix. The 
 * rows are shifted as follows: the first row is left as is then the ith row is 
 * rotated i bytes to the left.
 * 
 * @param in    A 128-bit block of data
 */
void shiftRows( Byte *in ) {
    #if defined VERBOSE
        char instring[BLOCK_STR_LEN];
    #if defined VVERBOSE
        prettyPrint(in, instring);
        printf( "shiftRows block in  %s\n", instring );
    #endif
    #endif
    
    Byte tmp[BLOCK_SIZE];
    
    /* Row i is shifted i places to the left */
    for (size_t i = 0; i < COLUMNS; ++i) {
        for (size_t j = 0; j < ROWS; ++j) {
            tmp[ i + ROWS * j ] = in[ i + ROWS * ((j+i)%COLUMNS) ];
        }
    }

    /* Copy tmp into in (if you want to you can just return tmp here */
    for (size_t i = 0; i < BLOCK_SIZE; ++i)
        in[i] = tmp[i];
    
    #if defined VERBOSE
        prettyPrint(in, instring);
        printf( "Row shifted:        %s\n", instring );
    #endif
    return;
}

/**
 * Jumbles a 128-bit block according to the mix columns step of AES.
 * 
 * The 128-bit block is arranged in a 4x4 matrix of bytes. The each column is 
 * multiplied by the matrix:
 * 2 3 1 1
 * 1 2 3 1
 * 1 1 2 3
 * 3 1 1 2
 * where multiplication is carried out in Rijndael's Galois field
 * 
 * @param in    A 128-bit block of data to be mixed
 */
void mixColumns( Byte *in ) {
    #if defined VERBOSE
        char instring[BLOCK_STR_LEN];
    #if defined VVERBOSE    
        prettyPrint(in, instring);
        printf( "mixColumns block in  %s\n", instring );
    #endif
    #endif
    
    Byte tmp[BLOCK_SIZE];
    Byte twiceIn[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        /* First make a copy of the input */
        tmp[i] = in[i];
        /* Multiplication by 2 is just bitshifting unless the highest bit is 
        set, then we also have to xor with 0x1b */
        twiceIn[i] = (in[i] << 1 ) ^ ( 0x1b & -(in[i] >> 7) );
    }
    for (size_t i = 0; i < COLUMNS; ++i) {
        /* Perform the matrix multiplication for column j */
        /* 2 * a0 + a3 + a2 + 3 * a1 */
        in[0 + 4*i] = twiceIn[0 + 4*i] ^ tmp[3 + 4*i] ^ tmp[2 + 4*i] ^ twiceIn[1 + 4*i] ^ tmp[1 + 4*i];
        /* 2 * a1 + a0 + a3 + 3 * a2 */
        in[1 + 4*i] = twiceIn[1 + 4*i] ^ tmp[0 + 4*i] ^ tmp[3 + 4*i] ^ twiceIn[2 + 4*i] ^ tmp[2 + 4*i];
        /* 2 * a2 + a1 + a0 + 3 * a3 */
        in[2 + 4*i] = twiceIn[2 + 4*i] ^ tmp[1 + 4*i] ^ tmp[0 + 4*i] ^ twiceIn[3 + 4*i] ^ tmp[3 + 4*i];
        /* 2 * a3 + a2 + a1 + 3 * a0 */
        in[3 + 4*i] = twiceIn[3 + 4*i] ^ tmp[2 + 4*i] ^ tmp[1 + 4*i] ^ twiceIn[0 + 4*i] ^ tmp[0 + 4*i];
    }

    #if defined VERBOSE
        prettyPrint(in, instring);
        printf( "Column mixed:       %s\n", instring );
    #endif
    return;
}

/**
 * Adds the round key provided.
 * 
 * Performs a bytewise xor between in and roundkey.
 * @param in        128-bit block of data
 * @param roundkey  the round key for that round.
 */
void addroundkey( Byte *in, Byte *roundkey ) {
    #if defined VERBOSE
        char instring[BLOCK_STR_LEN];
    #if defined VVERBOSE
        char keystring[BLOCK_STR_LEN];
        prettyPrint(roundkey, keystring);
        printf( "Adding key:         %s\n", keystring );
        prettyPrint(in, instring);
        printf( "To block:           %s\n", instring );
    #endif
    #endif
    
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        in[i] ^= roundkey[i];
    }

    #if defined VERBOSE
        prettyPrint(in, instring);
        printf( "Key added:          %s\n", instring );
    #endif
    return;
}

/**
 * Encrypt a 128-bit block of data according to AES-128 using the key provided.
 * 
 * @param data      A 128-bit block of data
 * @param key       A 128-bit key
 * @param cipher    A buffer to hold a 128-bit block of encrypted data
 */
void AESencrypt( Byte *data, Byte *key, Byte *cipher ) {
    #if defined VERBOSE
        char datastring[BLOCK_STR_LEN];
        char keystring[BLOCK_STR_LEN];
        char cipherstring[BLOCK_STR_LEN];
        prettyPrint(data, datastring);
        prettyPrint(key, keystring);
        printf( "Encrypting with key:\n%s\n", keystring );
        printf( "Data:\n%s\n", datastring );
    #endif
    
    /* Copy data into cipher */
    for (size_t i = 0; i < BLOCK_SIZE; ++i)
        cipher[i] = data[i];

    /* Initialise the key schedule */
    Byte **keySchedule;
    keySchedule = malloc( (ROUND_KEYS + 1)*sizeof(Byte*) );
    for (size_t i = 0; i < ROUND_KEYS + 1; ++i) {
        keySchedule[i] = malloc( BYTES_PER_KEY * sizeof(Byte) );
    }
    #if defined VERBOSE
        printf("Generating key schedule\n");
    #endif
    /* Generate the key schedule */
    generateKeySchedule( key, keySchedule );
    #if defined VERBOSE
        for (size_t i = 0; i <= ROUND_KEYS; ++i) {
            prettyPrint(keySchedule[i], keystring);
            printf("Key for Round %i: %s\n", (int) i, keystring);
        }
    #endif

    #if defined VERBOSE
        printf("\n--Initial Round--\n");
    #endif
    /* Initial round key addition */
    addroundkey( cipher, keySchedule[0] );

    /* Perform round transformations */
    for (size_t round = 1; round < ROUND_KEYS; ++round) {
        #if defined VERBOSE
            printf("\n--Round %i--\n", (int) round);
            prettyPrint(cipher, cipherstring);
            printf("Current state:      %s\n", cipherstring);
        #endif
        subBytes( cipher );
        shiftRows( cipher );
        mixColumns( cipher );
        addroundkey( cipher, keySchedule[round] );
    }

    #if defined VERBOSE
        printf("\n--Round %i--\n", ROUND_KEYS);
    #endif
    /* Don't mix columns for final round */
    subBytes( cipher );
    shiftRows( cipher );
    addroundkey( cipher, keySchedule[ROUND_KEYS] );

    #if defined VERBOSE
        printf("\n==Final Result==\n");
        prettyPrint(cipher, cipherstring);
        printf("%s\n", cipherstring);
    #endif
    return;
}

# if defined TEST
int main () {
    #if defined TEST1
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
        printf("rotateByteLeft and rotateByteRight passed testing!\n");
    }

    /* Testing for rotateWordLeft and rotateWordRight*/
    {
        Byte word[] = {0x01, 0x02, 0x03, 0x04};
        Byte testword1[] = {0x02, 0x03, 0x04, 0x01};
        Byte testword2[] = {0x04, 0x01, 0x02, 0x03};
        Byte test[4];
        rotateWordLeft(word, test);
        for (size_t i = 0; i < 4; ++i) {
            assert(test[i] == testword1[i]);
        }
        rotateWordRight(word, test);
        for (size_t i = 0; i < 4; ++i) {
            assert(test[i] == testword2[i]);
        }
        printf("rotateWordLeft and rotateWordRight passed testing!\n");
    }

    /* Testing for roundconstant */
    {
        Byte testvectors[] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a};
        for (size_t i = 1; i < 16; ++i) {
            assert( roundconstant(i) == testvectors[i] );
        }
        printf("roundconstant passed testing!\n");
    }

    /* Testing for sboxSub */
    {
        Byte testword[] = {0x00, 0x01, 0x02, 0x03};
        Byte result[4];
        Byte cmp[] = {0x63, 0x7c, 0x77, 0x7b};
        sboxSub(testword, result);
        for (size_t i = 0; i < 4; ++i) {
            assert( result[i] == cmp[i] );
        }
        printf("sboxSub testing passed!\n");
    }

    /* Testing for generateKeySchedule */
    {
        Byte *keySchedule[ROUND_KEYS + 1];
        for (size_t i = 0; i < ROUND_KEYS + 1; ++i) {
            keySchedule[i] = malloc( BYTES_PER_KEY * sizeof(Byte) );
        }
        Byte testKey[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        generateKeySchedule( testKey, keySchedule );
        Byte answer[][16] = {
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 
            {0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe}, 
            {0xb6, 0x92, 0xcf, 0x0b, 0x64, 0x3d, 0xbd, 0xf1, 0xbe, 0x9b, 0xc5, 0x00, 0x68, 0x30, 0xb3, 0xfe}, 
            {0xb6, 0xff, 0x74, 0x4e, 0xd2, 0xc2, 0xc9, 0xbf, 0x6c, 0x59, 0x0c, 0xbf, 0x04, 0x69, 0xbf, 0x41}, 
            {0x47, 0xf7, 0xf7, 0xbc, 0x95, 0x35, 0x3e, 0x03, 0xf9, 0x6c, 0x32, 0xbc, 0xfd, 0x05, 0x8d, 0xfd}, 
            {0x3c, 0xaa, 0xa3, 0xe8, 0xa9, 0x9f, 0x9d, 0xeb, 0x50, 0xf3, 0xaf, 0x57, 0xad, 0xf6, 0x22, 0xaa}, 
            {0x5e, 0x39, 0x0f, 0x7d, 0xf7, 0xa6, 0x92, 0x96, 0xa7, 0x55, 0x3d, 0xc1, 0x0a, 0xa3, 0x1f, 0x6b}, 
            {0x14, 0xf9, 0x70, 0x1a, 0xe3, 0x5f, 0xe2, 0x8c, 0x44, 0x0a, 0xdf, 0x4d, 0x4e, 0xa9, 0xc0, 0x26}, 
            {0x47, 0x43, 0x87, 0x35, 0xa4, 0x1c, 0x65, 0xb9, 0xe0, 0x16, 0xba, 0xf4, 0xae, 0xbf, 0x7a, 0xd2}, 
            {0x54, 0x99, 0x32, 0xd1, 0xf0, 0x85, 0x57, 0x68, 0x10, 0x93, 0xed, 0x9c, 0xbe, 0x2c, 0x97, 0x4e}, 
            {0x13, 0x11, 0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17, 0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5}
        };
        for (int i = 0; i < 11; ++i) {
            for (int j = 0 ; j < 16; ++j) {
                // printf("testing %i %i", i, j);
                assert(keySchedule[i][j] == answer[i][j]);
            }
        }
        Byte testKey2[] = {0x69, 0x20, 0xe2, 0x99, 0xa5, 0x20, 0x2a, 0x6d, 0x65, 0x6e, 0x63, 0x68, 0x69, 0x74, 0x6f, 0x2a};
        generateKeySchedule( testKey2, keySchedule );
        Byte answer2[][16] = {
            {0x69, 0x20, 0xe2, 0x99, 0xa5, 0x20, 0x2a, 0x6d, 0x65, 0x6e, 0x63, 0x68, 0x69, 0x74, 0x6f, 0x2a}, 
            {0xfa, 0x88, 0x07, 0x60, 0x5f, 0xa8, 0x2d, 0x0d, 0x3a, 0xc6, 0x4e, 0x65, 0x53, 0xb2, 0x21, 0x4f}, 
            {0xcf, 0x75, 0x83, 0x8d, 0x90, 0xdd, 0xae, 0x80, 0xaa, 0x1b, 0xe0, 0xe5, 0xf9, 0xa9, 0xc1, 0xaa}, 
            {0x18, 0x0d, 0x2f, 0x14, 0x88, 0xd0, 0x81, 0x94, 0x22, 0xcb, 0x61, 0x71, 0xdb, 0x62, 0xa0, 0xdb}, 
            {0xba, 0xed, 0x96, 0xad, 0x32, 0x3d, 0x17, 0x39, 0x10, 0xf6, 0x76, 0x48, 0xcb, 0x94, 0xd6, 0x93}, 
            {0x88, 0x1b, 0x4a, 0xb2, 0xba, 0x26, 0x5d, 0x8b, 0xaa, 0xd0, 0x2b, 0xc3, 0x61, 0x44, 0xfd, 0x50}, 
            {0xb3, 0x4f, 0x19, 0x5d, 0x09, 0x69, 0x44, 0xd6, 0xa3, 0xb9, 0x6f, 0x15, 0xc2, 0xfd, 0x92, 0x45}, 
            {0xa7, 0x00, 0x77, 0x78, 0xae, 0x69, 0x33, 0xae, 0x0d, 0xd0, 0x5c, 0xbb, 0xcf, 0x2d, 0xce, 0xfe}, 
            {0xff, 0x8b, 0xcc, 0xf2, 0x51, 0xe2, 0xff, 0x5c, 0x5c, 0x32, 0xa3, 0xe7, 0x93, 0x1f, 0x6d, 0x19}, 
            {0x24, 0xb7, 0x18, 0x2e, 0x75, 0x55, 0xe7, 0x72, 0x29, 0x67, 0x44, 0x95, 0xba, 0x78, 0x29, 0x8c}, 
            {0xae, 0x12, 0x7c, 0xda, 0xdb, 0x47, 0x9b, 0xa8, 0xf2, 0x20, 0xdf, 0x3d, 0x48, 0x58, 0xf6, 0xb1}
        };

        for (int i = 0; i < 11; ++i) {
            for (int j = 0 ; j < 16; ++j) {
                // printf("testing %i %i", i, j);
                assert(keySchedule[i][j] == answer2[i][j]);
            }
        }

        printf("generateKeySchedule passed the test!\n");
    }

    /* Test shift rows */
    {
        Byte in[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        Byte result[] = {0x00, 0x05, 0x0a, 0x0f, 0x04, 0x09, 0x0e, 0x03, 0x08, 0x0d, 0x02, 0x07, 0x0c, 0x01, 0x06, 0x0b};
        shiftRows(in);
        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            assert( in[i] == result[i] );
        }
        printf("shiftRows testing passed!\n");
    }

    /* Test mixColumns */
    {
        Byte in[] = {0xdb, 0x13, 0x53, 0x45, 0xf2, 0x0a, 0x22, 0x5c, 0x01, 0x01, 0x01, 0x01, 0x2d, 0x26, 0x31, 0x4c};
        Byte out[] = {0x8e, 0x4d, 0xa1, 0xbc, 0x9f, 0xdc, 0x58, 0x9d, 0x01, 0x01, 0x01, 0x01, 0x4d, 0x7e, 0xbd, 0xf8};
        mixColumns(in);
        for(size_t i = 0; i < BYTES_PER_KEY; ++i)
            assert( in[i] == out[i] );
        printf("mixColumns passed testing!\n");
    }
    /* Test prettyPrint */
    {
        Byte out[] = {0x0e, 0xdd, 0x33, 0xd3, 0xc6, 0x21, 0xe5, 0x46, 0x45, 0x5b, 0xd8, 0xba, 0x14, 0x18, 0xbe, 0xc8};
        char outstr[BLOCK_STR_LEN];
        prettyPrint(out, outstr);
        printf("%s\n", outstr);
    }
    #endif

    /* Test AESencrypt */
    {
        Byte key[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        Byte plain[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        Byte cipher[16];
        Byte out[] = {0x0e, 0xdd, 0x33, 0xd3, 0xc6, 0x21, 0xe5, 0x46, 0x45, 0x5b, 0xd8, 0xba, 0x14, 0x18, 0xbe, 0xc8};
        AESencrypt(plain, key, cipher);
        for (size_t i = 0; i < BLOCK_SIZE; ++i) 
            assert( cipher[i] == out[i] );

        printf("AESencrypt passed testing!\n");
    }
}
# endif