# Encryption Engine

This is a demo project for recording the implementation of Encryption in C/C++.

Require : openssl1.1.1

## evp_digest
Generating digest of message using Openssl EVP.  
The program receives arguments to determine which hash methods to use.  
usage:
```
./evpdigest md5
./evpdigest sha256
```

## evp_file_encryption 
Encrypt files using Openssl EVP.   
Baesd on the work by Amit Kulkarni  
interface:
```
void file_encrypt_decrypt(cipher_params_t *params, FILE *ifp, FILE *ofp)
```

## evp_file_encryption1
Encrypt files using Openssl EVP.  
Baesd on the example of www.openssl.org  

## string_encryption
Encrypt string without Openssl EVP.

