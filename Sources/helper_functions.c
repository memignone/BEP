#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../Headers/clefia.h"
#include "../Headers/helper_functions.h"
#define CLEFIABLOCKSIZE 16	/* 128 bit = 16 byte */

/**********************************
 * ECB - Electronic CodeBook mode *
 **********************************/
int encriptar_clefia_ecb(FILE* src, FILE* dst, int bits) {
	const unsigned char skey[32] = {	/* seed */
		0xffU,0xeeU,0xddU,0xccU,0xbbU,0xaaU,0x99U,0x88U,
		0x77U,0x66U,0x55U,0x44U,0x33U,0x22U,0x11U,0x00U,
		0xf0U,0xe0U,0xd0U,0xc0U,0xb0U,0xa0U,0x90U,0x80U,
		0x70U,0x60U,0x50U,0x40U,0x30U,0x20U,0x10U,0x00U
	};
	unsigned char rk[8 * 26 + 16];	/* 8 bytes x 26 rounds(max) + whitening keys */		/* key space */
	int r;	/* number of rounds */
	char bufferFile[CLEFIABLOCKSIZE], bufferCLEFIA[CLEFIABLOCKSIZE];
	
	r = ClefiaKeySet(rk, skey, bits);

	while(fread(bufferFile, sizeof(bufferFile), 1, src) > 0) {
		ClefiaEncrypt(bufferCLEFIA, bufferFile, rk, r);
		fwrite(bufferCLEFIA, sizeof(bufferCLEFIA), 1, dst);
	}
	return EXIT_SUCCESS;
}

int desencriptar_clefia_ecb(FILE* src, FILE* dst, int bits) {
	const unsigned char skey[32] = {	/* seed */
		0xffU,0xeeU,0xddU,0xccU,0xbbU,0xaaU,0x99U,0x88U,
		0x77U,0x66U,0x55U,0x44U,0x33U,0x22U,0x11U,0x00U,
		0xf0U,0xe0U,0xd0U,0xc0U,0xb0U,0xa0U,0x90U,0x80U,
		0x70U,0x60U,0x50U,0x40U,0x30U,0x20U,0x10U,0x00U
	};
	unsigned char rk[8 * 26 + 16]; /* 8 bytes x 26 rounds(max) + whitening keys */	 /* key space */
	int r;	/* number of rounds */
	char bufferFile[CLEFIABLOCKSIZE], bufferCLEFIA[CLEFIABLOCKSIZE];
	
	r = ClefiaKeySet(rk, skey, bits);

	while(fread(bufferFile, sizeof(bufferFile), 1, src) > 0) {
		ClefiaDecrypt(bufferCLEFIA, bufferFile, rk, r);
		fwrite(bufferCLEFIA, sizeof(bufferCLEFIA), 1, dst);
	}
	return EXIT_SUCCESS;
}

/************************************
 * CBC - Cipher Block Chaining mode *
 ************************************/
int encriptar_clefia_cbc(FILE* src, FILE* dst, int bits) {
	const unsigned char skey[32] = {	/* seed */
		0xffU,0xeeU,0xddU,0xccU,0xbbU,0xaaU,0x99U,0x88U,
		0x77U,0x66U,0x55U,0x44U,0x33U,0x22U,0x11U,0x00U,
		0xf0U,0xe0U,0xd0U,0xc0U,0xb0U,0xa0U,0x90U,0x80U,
		0x70U,0x60U,0x50U,0x40U,0x30U,0x20U,0x10U,0x00U
	};
	unsigned char rk[8 * 26 + 16];	/* 8 bytes x 26 rounds(max) + whitening keys */		/* key space */
	int r;	/* number of rounds */
	char bufferFile[CLEFIABLOCKSIZE], bufferCLEFIA[CLEFIABLOCKSIZE], bufferXor[CLEFIABLOCKSIZE];
	unsigned char iv[CLEFIABLOCKSIZE] = {	/* initialization vector */
		0x44U,0x81U,0xd0U,0xc0U,0xd0U,0xa0U,0x90U,0x80U,
		0x23U,0x23U,0x50U,0x40U,0x33U,0x22U,0x10U,0x00U
	};
	
	r = ClefiaKeySet(rk, skey, bits);

	while(fread(bufferFile, sizeof(bufferFile), 1, src) > 0) {
		ByteXor(bufferXor, bufferFile, iv, sizeof(iv));
		ClefiaEncrypt(bufferCLEFIA, bufferXor, rk, r);
		fwrite(bufferCLEFIA, sizeof(bufferCLEFIA), 1, dst);
		memcpy(iv, bufferCLEFIA, sizeof(iv));
	}
	return EXIT_SUCCESS;
}

int desencriptar_clefia_cbc(FILE* src, FILE* dst, int bits) {
	const unsigned char skey[32] = {	/* seed */
		0xffU,0xeeU,0xddU,0xccU,0xbbU,0xaaU,0x99U,0x88U,
		0x77U,0x66U,0x55U,0x44U,0x33U,0x22U,0x11U,0x00U,
		0xf0U,0xe0U,0xd0U,0xc0U,0xb0U,0xa0U,0x90U,0x80U,
		0x70U,0x60U,0x50U,0x40U,0x30U,0x20U,0x10U,0x00U
	};
	unsigned char rk[8 * 26 + 16]; /* 8 bytes x 26 rounds(max) + whitening keys */	 /* key space */
	int r;	/* number of rounds */
	char bufferFile[CLEFIABLOCKSIZE], bufferCLEFIA[CLEFIABLOCKSIZE], bufferXor[CLEFIABLOCKSIZE];
	unsigned char iv[CLEFIABLOCKSIZE] = {	/* initialization vector */
		0x44U,0x81U,0xd0U,0xc0U,0xd0U,0xa0U,0x90U,0x80U,
		0x23U,0x23U,0x50U,0x40U,0x33U,0x22U,0x10U,0x00U
	};
	
	r = ClefiaKeySet(rk, skey, bits);

	while(fread(bufferFile, sizeof(bufferFile), 1, src) > 0) {
		ClefiaDecrypt(bufferCLEFIA, bufferFile, rk, r);
		ByteXor(bufferXor, bufferCLEFIA, iv, sizeof(iv));
		fwrite(bufferXor, sizeof(bufferCLEFIA), 1, dst);
		memcpy(iv, bufferFile, sizeof(iv));
	}
	return EXIT_SUCCESS;
}

/**********************************
 * Functions used only for testing *
 **********************************/
void BytePut(const unsigned char *data, int bytelen) {
	while(bytelen-- > 0){
		printf("%02x", *data++);
	}
	printf("\n");
}

int test_vectors_CLEFIA(void) {
	const unsigned char skey[32] = {	/* seed */
	0xffU,0xeeU,0xddU,0xccU,0xbbU,0xaaU,0x99U,0x88U,
	0x77U,0x66U,0x55U,0x44U,0x33U,0x22U,0x11U,0x00U,
	0xf0U,0xe0U,0xd0U,0xc0U,0xb0U,0xa0U,0x90U,0x80U,
	0x70U,0x60U,0x50U,0x40U,0x30U,0x20U,0x10U,0x00U
	};
	const unsigned char pt[16] = {	/* plain text */
	0x00U,0x01U,0x02U,0x03U,0x04U,0x05U,0x06U,0x07U,
	0x08U,0x09U,0x0aU,0x0bU,0x0cU,0x0dU,0x0eU,0x0fU
	};
	unsigned char ct[16];
	unsigned char dst[16];
	unsigned char rk[8 * 26 + 16]; /* 8 bytes x 26 rounds(max) + whitening keys */
	int r; /* number of rounds */

	printf("--- Test ---\n");
	printf("plaintext:  "); BytePut(pt, 16);
	printf("secretkey:  "); BytePut(skey, 32);

	/* for 128-bit key */
	printf("--- CLEFIA-128 ---\n");
	/* encryption */
	r = ClefiaKeySet(rk, skey, 128);
	ClefiaEncrypt(dst, pt, rk, r);
	printf("ciphertext: "); BytePut(dst, 16);
	/* decryption */
	ByteCpy(ct, dst, 16);
	r = ClefiaKeySet(rk, skey, 128);
	ClefiaDecrypt(dst, ct, rk, r);
	printf("plaintext : "); BytePut(dst, 16);

	/* for 192-bit key */
	printf("--- CLEFIA-192 ---\n");
	/* encryption */
	r = ClefiaKeySet(rk, skey, 192);
	ClefiaEncrypt(dst, pt, rk, r);
	printf("ciphertext: "); BytePut(dst, 16);
	/* decryption */
	ByteCpy(ct, dst, 16);
	r = ClefiaKeySet(rk, skey, 192);
	ClefiaDecrypt(dst, ct, rk, r);
	printf("plaintext : "); BytePut(dst, 16);

	/* for 256-bit key */
	printf("--- CLEFIA-256 ---\n");
	/* encryption */
	r = ClefiaKeySet(rk, skey, 256);
	ClefiaEncrypt(dst, pt, rk, r);
	printf("ciphertext: "); BytePut(dst, 16);
	/* decryption */
	ByteCpy(ct, dst, 16);
	r = ClefiaKeySet(rk, skey, 256);
	ClefiaDecrypt(dst, ct, rk, r);
	printf("plaintext : "); BytePut(dst, 16);

	return 0;
}