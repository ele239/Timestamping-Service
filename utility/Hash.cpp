#ifndef HASH
#define HASH

#include "../include/const.h"

class Hash{

public:

    void calculateHash(const char* message, unsigned char* hash){
        
        unsigned int digest_len; 
        EVP_MD_CTX* ctx;

        ctx = EVP_MD_CTX_new();
        EVP_DigestInit(ctx, EVP_sha256());
        EVP_DigestUpdate(ctx, (unsigned char*)message, strlen(message));
        EVP_DigestFinal(ctx, hash, &digest_len);

        EVP_MD_CTX_free(ctx);
    }
    
    /*
    void printHash(unsigned char*h, int len){
        cout << "HASH: ";
        for (size_t i = 0; i < len; ++i) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') 
                          << static_cast<unsigned int>(h[i]);
            }
            cout <<endl;
    }
    */

    void hashToString(unsigned char* hash, char string_hash[]) {
        for(int i = 0; i < 32; i++) {
            sprintf(&string_hash[i * 2], "%02x", hash[i]);
        }
    }

};

#endif