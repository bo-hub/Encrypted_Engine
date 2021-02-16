#include <iostream>
#include <openssl/evp.h>
#include <openssl/aes.h>


int main(int, char**) {
    unsigned char *key=(unsigned char *)"012345678901234";
    unsigned char *text=(unsigned char *)"abcdefghijklmno";
    unsigned char out[100];
    unsigned char deout[100];
    AES_KEY rdkey;
    AES_KEY derdkey;
    AES_set_encrypt_key(key,128,&rdkey);
    AES_encrypt(text,out,&rdkey);
    printf("encrypted data : %s \n",out);
    AES_set_decrypt_key(key,128,&derdkey);
    AES_decrypt(out,deout,&derdkey);
    printf("decrypted data : %s \n",deout);
    return 0;
}
