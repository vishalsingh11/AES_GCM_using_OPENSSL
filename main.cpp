#include <iostream>
#include <openssl/bio.h>
#include <filesystem>
#include <fstream>
#include <chrono>

#include "base64.h"
#include "openssl/openssl.h"
#include "string.h"

#define DEBUG_ENABLED 1
#define DEBUG_PRINT_ENABLED 0

namespace fs = std::filesystem;

int main(void) {

    /* Just for better console log */
    std::cout << std::endl;

    /* 256 bit key */
    std::string encoded_key = "l+jiUpCws/KVktHQV7CHZtPPoZhH+UCvN+pTK8XC+/s=";
    std::vector<BYTE> vector_key = base64_decode(encoded_key);
    std::string key = std::string(vector_key.begin() , vector_key.end());

    /* 128 bit IV */
    std::string encoded_iv = "eaE8nrfOB/t8aft1";
    std::vector<BYTE> vector_encoded_iv = base64_decode(encoded_iv);
    std::string iv = std::string(vector_encoded_iv.begin() , vector_encoded_iv.end());

    /* Additional Data */
    std::string encoded_aad = "G3t+mHX7hyfegWfzderVOw==";
    std::vector<BYTE> vector_encoded_aad = base64_decode(encoded_aad);
    std::string aad = std::string(vector_encoded_aad.begin() , vector_encoded_aad.end());

    /* file to be encrypted */
    fs::path file_to_encrypt = "plaintext.txt";

    /* encrypted file */
    fs::path encrypted_file = "encrypted.enc";

    /* decrypted file */
    fs::path decrypted_file = "decrypted.txt";

    /* buffer for aad tag */
    unsigned char aad_tag[16];

    /* instantiate openssl */
    openssl openssl;
    /* length of encrypted message */
    int encrypted_file_len = 0;
    /* length of encrypted message */
    int decrypted_file_len = 0;

    /***********DEBUG***********/
    #if DEBUG_ENABLED
        std::cout << "KEY :: " << key << std::endl;
        std::cout << "KEY Length :: " << key.size() << std::endl;
        std::cout << std::endl;
        std::cout << "IV :: " << iv << std::endl;
        std::cout << "IV Length :: " << iv.size() << std::endl;
        std::cout << std::endl;
        std::cout << "AAD :: " << aad << std::endl;
        std::cout << "AAD Length :: " << aad.size() << std::endl;
        std::cout << std::endl;
    #endif
    /***********END***********/

    /* encrypt message */
    auto result = openssl.encrypt(file_to_encrypt , (unsigned char*)key.c_str() , (unsigned char*)iv.c_str() , iv.size() , encrypted_file , &encrypted_file_len , (unsigned char*)aad.c_str() , aad.size() , aad_tag);

    if(result == true){
        std::cout << "Encryption is successful " << std::endl;
        std::cout << std::endl;
    } else {
        std::cout << "Encryption failed " << std::endl;
        abort();
    }

    /* Capture start time */
    auto start_time = std::chrono::high_resolution_clock::now();
    /* decrypt message */
    result = openssl.decrypt(encrypted_file , encrypted_file_len , (unsigned char*)key.c_str() , (unsigned char*)iv.c_str() , iv.size() , decrypted_file , &decrypted_file_len , (unsigned char*)aad.c_str() , aad.size() , aad_tag);
    /* Capture end time*/
    auto end_time = std::chrono::high_resolution_clock::now();

    if(result == true){
        std::cout << "Decryption is successful " << std::endl;
        std::cout << std::endl;
    } else {
        std::cout << "Decryption failed " << std::endl;
        abort();
    }

    #if DEBUG_ENABLED
        /***********DEBUG***********/
        std::cout << "Plain Data filename :: " << file_to_encrypt.string() << std::endl;
        std::cout << "Length of Plain Data :: " << fs::file_size(file_to_encrypt) << std::endl;
        std::cout << std::endl;
        std::cout << "Encrypted Data filename :: " << encrypted_file.string() << std::endl;
        std::cout << "Length of Encrypted Data :: " << fs::file_size(encrypted_file) << std::endl;
        std::cout << std::endl;
        std::cout << "Decrypted Data filename :: " << decrypted_file.string() << std::endl;
        std::cout << "Length of Decrypted Data :: " << fs::file_size(decrypted_file) << std::endl;
        std::cout << std::endl;
        std::cout << "Time taken to decrypt " << (fs::file_size(encrypted_file)/(1024*1024)) << " MB of file/data is :: " << std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count() << " ms" << std::endl;
        std::cout << std::endl;

        #if DEBUG_PRINT_ENABLED
            std::cout << "Encrypted text is :: " << std::endl;
            std::ifstream e_file(encrypted_file);
            if(e_file.is_open()){
                std::cout << e_file.rdbuf() << std::endl;
            }

            std::cout << "Encrypted text is :: " << std::endl;
            std::ifstream d_file(decrypted_file);
            if(d_file.is_open()){
                std::cout << d_file.rdbuf() << std::endl;
            }
        #endif
    #endif

    /***********END***********/

    return 0;
}