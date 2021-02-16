#include<openssl/evp.h>
#include<openssl/err.h>
#include<stdio.h>

int do_crypt(FILE *in, FILE *out, int do_encrypt);

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{
    // FILE *infile;
    // FILE *outfile;
    // infile = fopen("inputtext","rb");
    // outfile =fopen("outputfile","wb");
    // do_crypt(infile,outfile,1);
    FILE *infile1;
    FILE *outfile1;
    infile1 = fopen("outputfile","rb");
    outfile1 =fopen("deoutfile","wb");
    do_crypt(infile1,outfile1,0);
    return 0;
}

int do_crypt(FILE *in, FILE *out, int do_encrypt)
{
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;
    /*
     * Bogus key and IV: we'd normally set these from
     * another source.
     */
    unsigned char key[] = "0123456789abcdeF";
    unsigned char iv[] = "1234567887654321";

    /* Don't set key or IV right away; we want to check lengths */
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
                       do_encrypt);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    /* Now we can set key and IV */
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    for (;;) {
        inlen = fread(inbuf, 1, 1024, in);
        if (inlen <= 0)
            break;
        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            /* Error */
            printf("errors in update cipher!\n");
            handleErrors();
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
        /* Error */
        printf("errors in final cipher!\n");
        handleErrors();
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}