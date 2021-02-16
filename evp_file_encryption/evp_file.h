//
// Created by bob on 2021/2/11.
//

#ifndef EVP_FILE_ENCRYPTED_ENGINE_EVP_FILE_H
#define EVP_FILE_ENCRYPTED_ENGINE_EVP_FILE_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define ERR_EVP_CIPHER_INIT -1
#define ERR_EVP_CIPHER_UPDATE -2
#define ERR_EVP_CIPHER_FINAL -3
#define ERR_EVP_CTX_NEW -4

#define AES_256_KEY_SIZE 32
#define AES_128_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define SM4_128_KEY_SIZE 16
#define SM4_BLOCK_SIZE 16
#define BUFSIZE 1024

typedef struct _cipher_params_t{
    unsigned char *key;
    unsigned char *iv;
    unsigned int encrypt;
    const EVP_CIPHER *cipher_type;
}cipher_params_t;

void cleanup(cipher_params_t *params, FILE *ifp, FILE *ofp, int rc);

void file_encrypt_decrypt(cipher_params_t *params, FILE *ifp, FILE *ofp);

#endif //EVP_FILE_ENCRYPTED_ENGINE_EVP_FILE_H
