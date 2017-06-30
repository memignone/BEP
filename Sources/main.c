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
			printf("Este programa espera como entrada: path a la imagen, nombre de la nueva imagen, el modo de operacion [E/D] y la cantidad de bits de la key[128/192/256]:\n");
			printf("E - Para ENCRIPTAR la imagen.\n");
			printf("D - Para DESENCRIPTAR la imagen.\n");
			exit(EXIT_SUCCESS);
		}
		else {
			if(argc == 5 && (strcmp(argv[3], "E") == 0 || strcmp(argv[3], "D") == 0) &&
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
					printf("path to new image file is too long.\n");
					exit(EXIT_FAILURE);
				}

				newFile = fopen(newFilePath, "wb");
				if (newFile==NULL) {
					printf("New image file not opened.\n");
					exit(EXIT_FAILURE);
				}
				
				// Copy original BMP header to newFile
				fread(bufferHeader, (long)HEADERSIZE, 1, originalBMP);
				fwrite(bufferHeader, sizeof(bufferHeader), 1, newFile);
				
				// CLEFIA encryption / decryption
				switch (atoi(argv[4])) {
					case 128:
						printf("--- CLEFIA-128 ---\n");
						strcmp(argv[3], "E") == 0 ?
							encriptar_clefia(originalBMP, newFile, 128) :
							desencriptar_clefia(originalBMP, newFile, 128);
						break;
					case 192:
						printf("--- CLEFIA-192 ---\n");
						strcmp(argv[3], "E") == 0 ?
							encriptar_clefia(originalBMP, newFile, 192) :
							desencriptar_clefia(originalBMP, newFile, 192);
						break;
					case 256:
						printf("--- CLEFIA-256 ---\n");
						strcmp(argv[3], "E") == 0 ?
							encriptar_clefia(originalBMP, newFile, 256) :
							desencriptar_clefia(originalBMP, newFile, 256);
						break;
					default:
						printf("Default de SWITCH");
						exit(EXIT_FAILURE);
						break;
				}

				fclose(originalBMP);
				fclose(newFile);
			}
			else {
				if(argv[3] && strcmp(argv[3], "E") != 0 && strcmp(argv[3], "D") != 0) {
					printf("Los modos de operacion son 'E' o 'D'.\n");
				}
				if(argv[4] && atoi(argv[4]) != 128 && atoi(argv[4]) != 192 && atoi(argv[4]) != 256) {
					printf("La clave solamente puede tener 128, 192 o 256 bits.\n");
				}
				printf("Para consultar la ayuda ingrese \"-?\" o \"-h\".\n");
				exit(EXIT_SUCCESS);
			}
		}
	}
}
