#ifndef AES_H
#define AES_H

typedef unsigned char Byte;

void prettyPrint( Byte *in, char *string );
bool compareBlock( Byte *a, Byte *b );

Byte rotateByteLeft( Byte in, int n );
Byte rotateByteRight( Byte in, int n );
void rotateWordLeft(Byte *in, Byte *out);
void rotateWordRight(Byte *in, Byte *out);
Byte roundconstant( int round );
void sboxSub( Byte *word, Byte *subbedWord );
void generateKeySchedule( Byte *initialKey, Byte **keySchedule );

void addroundkey( Byte *in, Byte *roundkey );
void subBytes( Byte *in );
void shiftRows( Byte *in );
void mixColumns( Byte *in );
void AESencrypt( Byte *data, Byte *key, Byte *cipher );

void inv_subBytes( Byte *in );
void inv_shiftRows( Byte *in );
void inv_mixColumns ( Byte *in );
void AESdecrypt( Byte *cipher, Byte *key, Byte *plain );
#endif