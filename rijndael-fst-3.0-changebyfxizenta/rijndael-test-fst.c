#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> 
#include "rijndael-api-fst.h"


typedef struct {
    int len;
    BYTE * text;
} inputInstance;

BYTE unhex_sub(char x) {
    if (x >= '0' && x <= '9') {
        return x - '0';
    } else if (x >= 'a' && x <= 'f') {
        return x - 'a' + 10;
    } else if (x >= 'A' && x <= 'F') {
        return x - 'A' + 10;
    } else {
        return 0xff;
    }
}

int unhex(char *hex, BYTE *bin, int hexLen) {
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

void printBytes(inputInstance *text) {
    for (int i = 0; i < text->len; i++) {
        printf("%02x", text->text[i]);
    }
    printf("\n");
    return;
}

void getCons(keyInstance *key, cipherInstance *cipher, inputInstance *input, inputInstance *output,BYTE _direction,char *_keyMaterial,BYTE _mode) {
    char _IV[MAX_IV_SIZE+1] = {0};
    if (_mode == MODE_ECB) {
        cipherInit(cipher, _mode, NULL);
    } else if (_mode == MODE_CBC) {
        printf("\nPlease enter your IV (HEX): \n");
        printf("-> ");
        while(scanf("%32s", _IV)) {
            if (cipherInit(cipher, _mode, _IV) != TRUE) {
                printf("Please enter the required format ! \n-> ");
            }
            else break;
        }
    } else {
        printf("Please enter the required format ! \n-> ");
    }

    // get input m or c
    int inputLen;
    char * inputHex;
    printf("\nPlease enter Plaintext/Ciphertext and it's length (HEX) \n-> length: ");
    while(scanf("%d", &inputLen)) {
        if ((inputLen & 1) != 0) {
            printf("Please enter the required format ! \n-> length: ");
        }
        else break;
    }
    inputHex = malloc(inputLen);
    input->len = inputLen/2;
    input->text = malloc(input->len);
    printf("-> Plaintext/Ciphertext: ");
    while(scanf("%s", inputHex)) {
        if (unhex(inputHex, input->text, inputLen) != TRUE) {
            printf("Please enter the required format ! \n-> laintext/Ciphertext: ");
        }
        else break;
    }
    output->len = ((inputLen/2-1)/8+1)*8;
    output->text = malloc(output->len);
    free(inputHex);
    return;
}


//api
void rijndaelAPI(keyInstance *key, cipherInstance *cipher, inputInstance *input, inputInstance *output) {
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

int main(int argc,char *argv[]) {
    keyInstance keyInst;
    cipherInstance cipherInst;
    inputInstance inputInst, outputInst;
    int opt = 0;
    BYTE _direction=0;
    char *_keyMaterial=NULL;
    BYTE _mode=1;
    //argv
    while((opt = getopt(argc, argv, "h:t:k:m:")) != -1) {
        switch(opt) {
            case 'h':
                printf("Usage: ./rijndael-test-fst -t <E/D> -k <KEY_HEX> -m <ECB/CBC>\n");
                return 0;
            case 't':
                if (!strcmp("E", optarg)) {
                    _direction = 0;
                } else if (!strcmp("D", optarg)) {
                    _direction = 1;
                } else {
                    printf("Error: Option type must be E or D!\n");
                    return -1;
                }
                break;
            case 'k':
                _keyMaterial = optarg;
                int _keyLen = strlen(_keyMaterial);
                if (makeKey(&keyInst, _direction, _keyLen * 4, _keyMaterial) != TRUE) {
                    printf("Error: Please enter the right key ! \n-> ");
                }
                break;
            case 'm':
                if (!strcmp("ECB", optarg)) {
                    _mode = 1;
                } else if (!strcmp("CBC", optarg)) {
                    _mode = 2;
                } else {
                    printf("Error: Option type must be ECB or CBC!\n");
                    return -1;
                }
                break;
        }
    }
    getCons(&keyInst, &cipherInst, &inputInst, &outputInst,_direction,_keyMaterial,_mode);
    rijndaelAPI(&keyInst, &cipherInst, &inputInst, &outputInst);
    printf("\nResult is:\n ");
    printBytes(&outputInst);
    free(inputInst.text);
    free(outputInst.text);
    return 0;
}