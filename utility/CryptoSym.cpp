#ifndef CRYPTOSYM
#define CRYPTOSYM

#include "../include/const.h"

class CryptoSym{

    private:

    EVP_CIPHER_CTX* enc_ctx = nullptr;
    EVP_CIPHER_CTX* dec_ctx = nullptr;
    unsigned int tx_counter = 0;
    unsigned int rx_counter = 0;

    public:

    CryptoSym(unsigned char* key){
        enc_ctx = EVP_CIPHER_CTX_new();
        dec_ctx = EVP_CIPHER_CTX_new();

        EVP_EncryptInit(enc_ctx, EVP_aes_256_gcm(), key, nullptr);
        EVP_DecryptInit(dec_ctx, EVP_aes_256_gcm(), key, nullptr);
        OPENSSL_cleanse((void*)key,EVP_CIPHER_key_length(EVP_aes_256_gcm()));
    }

    ~CryptoSym(){
        if(enc_ctx){
            EVP_CIPHER_CTX_free(enc_ctx);
            enc_ctx = nullptr;
        }

        if(dec_ctx){
            EVP_CIPHER_CTX_free(dec_ctx);
            dec_ctx = nullptr;
        }
    }

    status encrypt(const unsigned char* plaintext, int plaintext_len, const unsigned char* iv,
        unsigned char* tag, unsigned char* ciphertext_out, int* cipherlen_out){

        int len;
        int ciphertext_len;

        EVP_EncryptInit(enc_ctx, nullptr, nullptr, iv);

        EVP_EncryptUpdate(enc_ctx, nullptr, &len, (unsigned char*)&tx_counter, sizeof(tx_counter));
        EVP_EncryptUpdate(enc_ctx, ciphertext_out, &len, plaintext, plaintext_len);
        ciphertext_len = len;
        
        EVP_EncryptFinal(enc_ctx, ciphertext_out + ciphertext_len, &len);
        EVP_CIPHER_CTX_ctrl(enc_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
        
        ciphertext_len += len;
        
        *cipherlen_out = ciphertext_len;
        tx_counter++;

        return status::OK;
    }
    

    status decrypt(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* iv,
        const unsigned char* tag, unsigned char* plaintext_out, int* plainlen_out){

        int len;
        int plaintext_len;

        EVP_DecryptInit(dec_ctx, nullptr, nullptr, iv);

        EVP_DecryptUpdate(dec_ctx, nullptr, &len, (unsigned char*)&rx_counter, sizeof(rx_counter));

        EVP_DecryptUpdate(dec_ctx, plaintext_out, &len, ciphertext, ciphertext_len);
        plaintext_len = len;

        EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
        int outcome = EVP_DecryptFinal(dec_ctx, plaintext_out + plaintext_len, &len);
        
        if(outcome > 0){
            plaintext_len += len;
            *plainlen_out = plaintext_len;
            rx_counter++;
            return status:: OK;
        }
        
        return status::ERROR;
    }

    
};

#endif