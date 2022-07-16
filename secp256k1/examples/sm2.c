#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../src/sm3.h"
#include <secp256k1.h>
#include "random.h"

int main(void){
    /*
        我们省略了对待签名消息哈希的过程，既:
        msg_hash = H(M)。
        如果你自由一点，可以用sm3替代哈希函数H对消息进行哈希。
    */
//    unsigned char msg_hash[32] = {
//        0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
//        0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
//        0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
//        0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
//    };
    unsigned char *data="华南师范大学网络工程系";
    unsigned char msg_hash[32];
    unsigned char message[32];
    unsigned char ciphertext[128];
    unsigned char seckey[32];
    unsigned char randomize[32];
    unsigned char compressed_pubkey[33];
    unsigned char serialized_signature[64];
    SM3_CTX sm3_ctx;
    size_t len;
    int is_signature_valid;
    int return_val;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;

    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx,data,sizeof(data));
    sm3_finish(&sm3_ctx,msg_hash);

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }

    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    /*** Key Generation ***/

    /*
        私钥属于[1,n],n是曲线的阶
    */
    while (1) {
        if (!fill_random(seckey, sizeof(seckey))) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (secp256k1_ec_seckey_verify(ctx, seckey)) {
            break;
        }
    }

    return_val = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
    assert(return_val);

    len = sizeof(compressed_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);
    /* Should be the same size as the size of the output, because we passed a 33 byte array. */
    assert(len == sizeof(compressed_pubkey));

    /*** Signing ***/
    /*
     *  you need to implement secp256k1_sm2_sign function
    */
    return_val = secp256k1_sm2_sign(ctx, &sig, msg_hash, seckey, NULL, NULL);
    assert(return_val);

    /* Serialize the signature in a compact form. Should always return 1
     * according to the documentation in secp256k1.h. */
    return_val = secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, &sig);
    assert(return_val);

    /*** Verification ***/

    /* Deserialize the signature. This will return 0 if the signature can't be parsed correctly. */
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, serialized_signature)) {
        printf("Failed parsing the signature\n");
        return 1;
    }

    /* Deserialize the public key. This will return 0 if the public key can't be parsed correctly. */
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, compressed_pubkey, sizeof(compressed_pubkey))) {
        printf("Failed parsing the public key\n");
        return 1;
    }

    /* Verify a signature. This will return 1 if it's valid and 0 if it's not. */
    /*
     * you need to implement secp256k1_sm2_verify function
    */
    is_signature_valid = secp256k1_sm2_verify(ctx, &sig, msg_hash, &pubkey);

    printf("Is the signature valid? %s\n", is_signature_valid ? "true" : "false");
    printf("Secret Key: ");
    print_hex(seckey, sizeof(seckey));
    printf("Public Key: ");
    print_hex(compressed_pubkey, sizeof(compressed_pubkey));
    printf("Signature: ");
    print_hex(serialized_signature, sizeof(serialized_signature));

    /*** Enctryption ***/
    return_val = secp256k1_sm2_encryption(ctx, ciphertext, msg_hash, sizeof(msg_hash), &pubkey, NULL, NULL);
    assert(return_val);

    /*** decrytion ***/
    return_val = secp256k1_sm2_decryption(message, sizeof(msg_hash), ciphertext, seckey);

    printf("Is the decrytion succeed? %s\n", return_val ? "true" : "false");

    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);

    /* It's best practice to try to clear secrets from memory after using them.
     * This is done because some bugs can allow an attacker to leak memory, for
     * example through "out of bounds" array access (see Heartbleed), Or the OS
     * swapping them to disk. Hence, we overwrite the secret key buffer with zeros.
     *
     * TODO: Prevent these writes from being optimized out, as any good compiler
     * will remove any writes that aren't used. */
    memset(seckey, 0, sizeof(seckey));

    return 0;
}