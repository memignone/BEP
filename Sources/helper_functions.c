#include <stdio.h>
#include <stdlib.h>
#include "../Headers/clefia.h"
#include "../Headers/helper_functions.h"
#define CLEFIABLOCKSIZE 16	/* 128 bit = 16 byte */

int encriptar_clefia(FILE* src, FILE* dst, int bits) {
	const unsigned char skey[32] = {	/* seed */
		0xffU,0xeeU,0xddU,0xccU,0xbbU,0xaaU,0x99U,0x88U,
		0x77U,0x66U,0x55U,0x44U,0x33U,0x22U,0x11U,0x00U,
		0xf0U,0xe0U,0xd0U,0xc0U,0xb0U,0xa0U,0x90U,0x80U,
		0x70U,0x60U,0x50U,0x40U,0x30U,0x20U,0x10U,0x00U
	};
  	unsigned char rk[8 * 26 + 16];	/* 8 bytes x 26 rounds(max) + whitening keys */		/* key space */
  	int r;	/* key codification code */
	char bufferFile[CLEFIABLOCKSIZE], bufferCLEFIA[CLEFIABLOCKSIZE];
	
	r = ClefiaKeySet(rk, skey, bits);

	while(fread(bufferFile, sizeof(bufferFile), 1, src) > 0) {
		ClefiaEncrypt(bufferCLEFIA, bufferFile, rk, r);
		fwrite(bufferCLEFIA, sizeof(bufferFile), 1, dst);
	}
	return EXIT_SUCCESS;
}

int desencriptar_clefia(FILE* src, FILE* dst, int bits) {
	const unsigned char skey[32] = {	/* seed */
		0xffU,0xeeU,0xddU,0xccU,0xbbU,0xaaU,0x99U,0x88U,
		0x77U,0x66U,0x55U,0x44U,0x33U,0x22U,0x11U,0x00U,
		0xf0U,0xe0U,0xd0U,0xc0U,0xb0U,0xa0U,0x90U,0x80U,
		0x70U,0x60U,0x50U,0x40U,0x30U,0x20U,0x10U,0x00U
	};
  	unsigned char rk[8 * 26 + 16]; /* 8 bytes x 26 rounds(max) + whitening keys */	 /* key space */
  	int r;	/* key codification code */
	char bufferFile[CLEFIABLOCKSIZE], bufferCLEFIA[CLEFIABLOCKSIZE];
	
	r = ClefiaKeySet(rk, skey, bits);

	while(fread(bufferFile, sizeof(bufferFile), 1, src) > 0) {
		ClefiaDecrypt(bufferCLEFIA, bufferFile, rk, r);
		fwrite(bufferCLEFIA, sizeof(bufferFile), 1, dst);
	}
	return EXIT_SUCCESS;
}
