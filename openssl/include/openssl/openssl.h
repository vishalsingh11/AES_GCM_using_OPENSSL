#ifndef OPENSSL_H
#define OPENSSL_H

#include <filesystem>
namespace fs = std::filesystem;

class openssl{

private:

    /*tbd*/

public:
    openssl();

    bool encrypt(
            fs::path file_to_encrypt, 
            unsigned char* key,
            unsigned char* iv, 
            unsigned int iv_len,
            fs::path encrypted_file,
            int* encrypted_file_len,
            unsigned char* aad,
            int aad_length,
            unsigned char* aad_tag);

    bool decrypt(
            fs::path encrypted_file, 
            int encrypted_file_len,
            unsigned char* key,
            unsigned char* iv, 
            unsigned int iv_len,
            fs::path decrypted_file,
            int* decrypted_file_len,
            unsigned char* aad,
            int aad_length,
            unsigned char* aad_tag);

    ~openssl();
};

#endif