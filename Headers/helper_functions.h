#ifndef HELPER_FUNCTIONS_H_INCLUDED
#define HELPER_FUNCTIONS_H_INCLUDED

int encriptar_clefia_ecb(FILE* src, FILE* dst, int bits);
int desencriptar_clefia_ecb(FILE* src, FILE* dst, int bits);

int encriptar_clefia_cbc(FILE* src, FILE* dst, int bits);
int desencriptar_clefia_cbc(FILE* src, FILE* dst, int bits);

void BytePut(const unsigned char *data, int bytelen);
int test_vectors_CLEFIA();

#endif
