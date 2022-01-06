#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rijndael-api-fst.h"

typedefstruct {
int len;
    BYTE * text;
} textInstance;

void printBytes(textInstance *text) {
for (int i = 0; i < text->len; i++) {
        printf("%02x", text->text[i]);
    }
    printf("\n");
return;
}

BYTE unhex_sub(char x) {
if (x >= '0' && x <= '9') {
return x - '0';
    }elseif (x >= 'a' && x <= 'f') {
return x - 'a' + 10;
    }elseif (x >= 'A' && x <= 'F') {
return x - 'A' + 10;
    }else {
return 0xff;
    }
}

int unhex(char *hex, BYTE *bin,int hexLen) {
for (int i = 0; i < hexLen; i += 2) {
        bin[i/2] = 0;
for (int j = 0; j < 2; j++) {
            BYTE tmp = unhex_sub(hex[i+j]);
if (tmp == 0xff) {
return FALSE;
            }
            bin[i/2] <<= 4;
            bin[i/2] |= tmp;
        }
    }
return TRUE;
}

void printMenu() {
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n");
    printf("    Welcome to the AES Tool.\n");
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n");
    printf("\n");
return;
}

void getCons(keyInstance *key, cipherInstance *cipher, textInstance *input, textInstance *output) {
// init keyBYTE _direction;
    printf("\nGive me your choice?\n");
    printf(" - input [0] to Encrypt\n");
    printf(" - input [1] to Decrypt\n");
    printf("-> ");
while(scanf("%hhd", &_direction)) {
if (_direction != DIR_ENCRYPT && _direction != DIR_DECRYPT) {
            printf("What? Again?\n-> ");
        }
elsebreak;
    }
char _keyMaterial[MAX_KEY_SIZE+1];
    printf("\nGive me your key? (in HEX encoding)\n");
    printf("-> ");
while(scanf("%64s", _keyMaterial)) {
int _keyLen = strlen(_keyMaterial);
if (makeKey(key, _direction, _keyLen * 4, _keyMaterial) != TRUE) {
            printf("What? Again?\n-> ");
        }
elsebreak;
    }

// init cipherBYTE _mode;
char _IV[MAX_IV_SIZE+1] = {0};
    printf("\nGive me your proc mode?\n");
    printf(" - input [1] to MODE_ECB\n");
    printf(" - input [2] to MODE_CBC\n");
    printf("-> ");
while(scanf("%hhd", &_mode)) {
if (_mode == MODE_ECB) {
            cipherInit(cipher, _mode, NULL);
break;
        }elseif (_mode == MODE_CBC) {
            printf("\nGive me your IV? (in HEX encoding)\n");
            printf("-> ");
while(scanf("%32s", _IV)) {
if (cipherInit(cipher, _mode, _IV) != TRUE) {
                    printf("What? Again?\n-> ");
                }
elsebreak;
            }
break;
        }else {
            printf("What? Again?\n-> ");
        }
    }

// get inputint inputLen;
char * inputHex;
    printf("\nGive a length and your input? (both in HEX encoding)\n-> length: ");
while(scanf("%d", &inputLen)) {
if ((inputLen & 1) != 0) {
            printf("What? Again?\n-> length: ");
        }
elsebreak;
    }
    inputHex = malloc(inputLen);
    input->len = inputLen/2;
    input->text = malloc(input->len);
    printf("-> input: ");
while(scanf("%s", inputHex)) {
if (unhex(inputHex, input->text, inputLen) != TRUE) {
            printf("What? Again?\n-> input: ");
        }
elsebreak;
    }
    output->len = ((inputLen/2-1)/8+1)*8;
    output->text = malloc(output->len);
    free(inputHex);
return;
}

void rijndaelAPI(keyInstance *key, cipherInstance *cipher, textInstance *input, textInstance *output) {
switch (key->direction) {
case DIR_ENCRYPT:
            padEncrypt(cipher, key, input->text, input->len, output->text);
break;
case DIR_DECRYPT:
            padDecrypt(cipher, key, input->text, input->len, output->text);
break;
    }
return;
}

int main() {
    keyInstance keyInst;
    cipherInstance cipherInst;
    textInstance inputInst, outputInst;
    printMenu();
    getCons(&keyInst, &cipherInst, &inputInst, &outputInst);
    rijndaelAPI(&keyInst, &cipherInst, &inputInst, &outputInst);
    printf("\n\nYour output is: ");
    printBytes(&outputInst);
    free(inputInst.text);
    free(outputInst.text);
return 0;
}