#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../Headers/clefia.h"
#include "../Headers/helper_functions.h"
#define HEADERSIZE 54		/* .bmp image files have a header 54 byte long */
#define PATHLENGTH 255


int main(int argc,char *argv[]) {
	char bmpImagePath[PATHLENGTH], newFilePath[PATHLENGTH], bufferHeader[HEADERSIZE];
	FILE *newFile, *originalBMP;


	if(argc > 1) {
		if(strcmp(argv[1], "-?") == 0 || strcmp(argv[1], "-h") == 0) {
			printf("Este programa sirve para encriptar o desencriptar una imagen (excluyendo el HEADER) tipo Windows Bitmap (.BMP) utilizando el algoritmo Clefia de Sony.\n");
			printf("Este programa espera como entrada: path a la imagen, nombre de la nueva imagen, el modo de operacion [E/D][ECB/CBC] y la cantidad de bits de la key[128/192/256]:\n");
			printf("1 - Para ENCRIPTAR en modo ECB.\n");
			printf("2 - Para DESENCRIPTAR en modo ECB.\n");
			printf("3 - Para ENCRIPTAR en modo CBC.\n");
			printf("4 - Para DESENCRIPTAR en modo CBC.\n");
			exit(EXIT_SUCCESS);
		}
		else {
			if(strcmp(argv[1], "-t") == 0 || strcmp(argv[1], "-test") == 0)
				test_vectors_CLEFIA();
			else {
				if(argc == 5 && (atoi(argv[3]) >= 1 && atoi(argv[3]) <= 4) &&
					(atoi(argv[4]) == 128 || atoi(argv[4]) == 192 || atoi(argv[4]) == 256)) {

					if(strlen(argv[1]) < PATHLENGTH)
						strcpy(bmpImagePath, argv[1]);
					else {
						printf("path to BMP image is too long.\n");
						exit(EXIT_FAILURE);
					}

					originalBMP = fopen(bmpImagePath, "rb");
					if (originalBMP == NULL) {
						printf("BMP not loaded.\n");
						exit(EXIT_FAILURE);
					}

					getcwd(newFilePath, sizeof(newFilePath)); // Get Current Working Directory Path
					strcat(newFilePath, "/"); // Append '/'
					if(strlen(newFilePath) + strlen(argv[2]) < PATHLENGTH)
						strcat(newFilePath, argv[2]);
					else {
						printf("Path to new image file is too long.\n");
						exit(EXIT_FAILURE);
					}

					newFile = fopen(newFilePath, "wb");
					if (newFile==NULL) {
						printf("New image file could not be opened.\n");
						exit(EXIT_FAILURE);
					}

					// Copy original BMP header to newFile
					fread(bufferHeader, (long)HEADERSIZE, 1, originalBMP);
					fwrite(bufferHeader, sizeof(bufferHeader), 1, newFile);

					// CLEFIA encryption / decryption
					switch(atoi(argv[3])){
					case 1:
						printf("CLEFIA %s bits ECB encryption mode\n", argv[4]);
						encriptar_clefia_ecb(originalBMP, newFile, atoi(argv[4]));
						break;
					case 2:
						printf("CLEFIA %s bits ECB decryption mode\n", argv[4]);
						desencriptar_clefia_ecb(originalBMP, newFile, atoi(argv[4]));
						break;
					case 3:
						printf("CLEFIA %s bits CBC encryption mode\n", argv[4]);
						encriptar_clefia_cbc(originalBMP, newFile, atoi(argv[4]));
						break;
					case 4:
						printf("CLEFIA %s bits CBC decryption mode\n", argv[4]);
						desencriptar_clefia_cbc(originalBMP, newFile, atoi(argv[4]));
						break;
					default:
						printf("Modo de operacion incorrecto\n");
						exit(EXIT_FAILURE);
						break;
					}

					fclose(originalBMP);
					fclose(newFile);
				}
				else {
					if(argv[3] && (atoi(argv[3]) < 1 || atoi(argv[3]) > 4)) {
						printf("Modo de operacion incorrecto.\n");
						printf("1 - Para ENCRIPTAR en modo ECB.\n");
						printf("2 - Para DESENCRIPTAR en modo ECB.\n");
						printf("3 - Para ENCRIPTAR en modo CBC.\n");
						printf("4 - Para DESENCRIPTAR en modo CBC.\n");
					}
					if(argv[4] && atoi(argv[4]) != 128 && atoi(argv[4]) != 192 && atoi(argv[4]) != 256) {
						printf("Las longuitudes de clave pueden ser: 128, 192 o 256 bits.\n");
					}
					printf("Para consultar la ayuda ingrese \"-?\" o \"-h\".\n");
					exit(EXIT_SUCCESS);
				}
			}
		}
	}
}
