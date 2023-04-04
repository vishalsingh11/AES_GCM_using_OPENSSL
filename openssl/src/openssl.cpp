#include <iostream>
#include <openssl/evp.h>
#include <fstream>

#include "openssl/openssl.h"

openssl::openssl(){
    /* Do Nothing */
}

openssl::~openssl(){
    /* Do Nothing */
}

bool openssl::encrypt(fs::path file_to_encrypt, unsigned char* key, unsigned char* iv,  unsigned int iv_len, fs::path encrypted_file, int* encrypted_file_len, unsigned char* aad, int aad_length, unsigned char* aad_tag){
    
    std::cout << "Encryption Started" << std::endl;

    EVP_CIPHER_CTX *ctx;

    int len;

    if(!fs::exists(file_to_encrypt)) {
        std::cout << "file :: " << file_to_encrypt << " not found !!!" << std::endl ;
        return false;
    }

    if(!fs::exists(encrypted_file)) {
        /* tbd :: create a file */
    }

    /* Null pointer check for Key and IV */
    if((nullptr == iv) || (nullptr == key)){
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;          
    }

    /* Create and initialize context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;
    }

    /* Initialize the encryption operation with AES-256 GCM cipher algorithm */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;        
    }

    /* tbd : change it to standard size */
    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx , EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)){
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;   
    }

    /* Initialize IV and Key */
    if(1 != EVP_EncryptInit_ex(ctx , NULL , NULL , key , iv)){
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;
    }

    /* set AAD data */
    if(1 != EVP_EncryptUpdate(ctx , NULL , &len , aad , aad_length)){
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;        
    }

    std::ifstream infile(file_to_encrypt.string());
    std::ofstream outfile(encrypted_file.string());

    /* buffer */
    auto message_to_encrypt = new unsigned char[fs::file_size(file_to_encrypt)];
    auto encrypted_message = new unsigned char[fs::file_size(file_to_encrypt)];

    /* copy data from file to buffer */
    infile.read((char*)message_to_encrypt , fs::file_size(file_to_encrypt));

    /* Provide the message to be encrypted, and obtain encrypted output */
    if(1 != EVP_EncryptUpdate(ctx , encrypted_message , &len , message_to_encrypt , fs::file_size(file_to_encrypt))){
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;
    }

    /* set length of encrypted message */
    *encrypted_file_len += len;

    /* Finalize the encryption */
    if(1 != EVP_EncryptFinal_ex(ctx , encrypted_message + len , &len)){
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;
    }

    /* Get additional tag value */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx , EVP_CTRL_GCM_GET_TAG , 16 , aad_tag)){
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;
    }

    /* set final length of encrypted message */
    *encrypted_file_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    /* copy encrypted data from encrypted output buffer to file */
    outfile.write((char*)encrypted_message , (long)*encrypted_file_len);

    return true;
}

bool openssl::decrypt(fs::path encrypted_file, int encrypted_file_len, unsigned char* key, unsigned char* iv, unsigned int iv_len, fs::path decrypted_file, int* decrypted_file_len, unsigned char* aad, int aad_length, unsigned char* aad_tag){
    
    std::cout << "Decryption Started" << std::endl;

    EVP_CIPHER_CTX *ctx;

    int len = 0;

    if(!fs::exists(encrypted_file)) {
        std::cout << "file :: " << encrypted_file << " not found !!!" << std::endl ;
        return false;
    }

    if(!fs::exists(decrypted_file)) {
        /* tbd :: create a file */
    }

    /* create and initialize context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;
    }

    /* Initialize the decryption operation */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;        
    }

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;   
    }

    /* Initialize IV and Key */
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;
    }

    /* set AAD data */
    if(1 != EVP_DecryptUpdate(ctx , NULL , &len , aad , aad_length)){
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;        
    }

    std::ifstream infile(encrypted_file.string());
    std::ofstream outfile(decrypted_file.string());

    /* chunk size */
    unsigned long chunk_size = 1024;

    /* buffer */
    auto encrypted_message = new unsigned char[chunk_size];
    auto decrypted_message = new unsigned char[chunk_size];

    while(1)
    {
        /* copy data from file to buffer */
        infile.read((char*)encrypted_message , chunk_size);

        /* Provide the message to be decrypted, and obtain decrypted output */
        if(1 != EVP_DecryptUpdate(ctx, decrypted_message, &len, encrypted_message, chunk_size)) {
            std::cout << "Error at line :: " << __LINE__ << std::endl;
            return false;
        }

        /* set length of decrypted message */
        *decrypted_file_len += len;

        /* copy decrypted data from decrypted output buffer to file */
        outfile.write((char*)decrypted_message , (long)len);

        if(*decrypted_file_len == fs::file_size(encrypted_file)){
            break;
        } else if((fs::file_size(encrypted_file) - *decrypted_file_len) < chunk_size) {
            chunk_size = fs::file_size(encrypted_file) - *decrypted_file_len;
        } else {
            /* do nothing */
        }
    }

    /* Set additional tag value */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx , EVP_CTRL_GCM_SET_TAG , 16 , aad_tag)){
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;
    }

    /* Finalize the decryption */
    if(EVP_DecryptFinal_ex(ctx , decrypted_message + len , &len) < 0 ) {
        std::cout << "Error at line :: " << __LINE__ << std::endl;
        return false;
    }

    /* set length of final decrypted message */
    *decrypted_file_len += len;

    /* clean up */
    EVP_CIPHER_CTX_free(ctx);

    /* copy decrypted data from decrypted output buffer to file */
    outfile.write((char*)decrypted_message , (long)len);

    return true;
}