#ifndef CRYPTO_ASYM
#define CRYPTO_ASYM

#include "../include/const.h"

class CryptoAsym{

    protected:
    
    EVP_PKEY* loadPublicKey(const char* filename) {
        
        FILE *f = fopen(filename, "rb");
        if (!f) {
            printf(ERROR_MESS "CAN'T OPEN PUBKEY FILE (path: %s)\n",filename);
            return NULL;
        }
        
        EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
        fclose(f);
        
        if (!pkey) {
            printf(ERROR_MESS "CAN'T READ PUBKEY (path: %s)\n",filename);
            return nullptr;
        }
        
        return pkey;
    }

    EVP_PKEY* loadPrivateKey(const char* filename) {
        FILE *f = fopen(filename, "rb");
        if (!f) {
            printf(ERROR_MESS "CAN'T OPEN PRIVKEY FILE (path: %s)\n",filename);
            return NULL;
        }
        
        EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        fclose(f);

        if (!pkey) {
            printf(ERROR_MESS "CAN'T READ PRIVKEY (path: %s)\n",filename);
            return nullptr;
        }

        return pkey;
    }

    EVP_PKEY* generateEphemeralKey() {
        EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
        
        return pkey;
    }

    status getRawEphemeralKey(EVP_PKEY* ek, unsigned char* raw_key){
        size_t key_len = EPH_KEY_SIZE;

        if (EVP_PKEY_get_raw_public_key(ek, raw_key, &key_len) != 1) {
            printf(ERROR_MESS "KEY CONVERSION ERROR!\n");
            return status::ERROR;
        }

        return status::OK;
    }

    status rebuildEphemeralKey(unsigned char* raw_key, EVP_PKEY** ek){
        *ek = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, raw_key, EPH_KEY_SIZE);
        
        if (!(*ek)) 
            return status::ERROR;

        return status::OK;
    }

    status calculateSharedSecret(EVP_PKEY* my_key, EVP_PKEY* other_key, unsigned char* shared_secret){

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key, NULL);

        if (EVP_PKEY_derive_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return status::ERROR;
        }

        if (EVP_PKEY_derive_set_peer(ctx, other_key) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return status::ERROR;
        }

        size_t shared_secret_dim = SHARED_SECRET_SIZE;
        if (EVP_PKEY_derive(ctx, NULL, &shared_secret_dim) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return status::ERROR;
        }

        if (EVP_PKEY_derive(ctx, shared_secret, &shared_secret_dim) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return status::ERROR;
        }

        EVP_PKEY_CTX_free(ctx);

        EVP_PKEY_free(my_key);         
        EVP_PKEY_free(other_key);         

        return status::OK;
        
    }

    status getSessionKey(unsigned char* shared_secret, unsigned char* session_key, unsigned char* nonces){

        EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
        EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);

        OSSL_PARAM params[5], *p = params;
        *p++ = OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA256", 0);
        *p++ = OSSL_PARAM_construct_octet_string("key", shared_secret, SHARED_SECRET_SIZE);

        *p++ = OSSL_PARAM_construct_octet_string("salt", nonces, NONCE_SIZE*2); 
        *p++ = OSSL_PARAM_construct_octet_string("info", (unsigned char*)"SEBA_ELE_HANDSHAKE", 18);
        *p = OSSL_PARAM_construct_end();

        if (EVP_KDF_derive(kctx, session_key, SHARED_SECRET_SIZE, params) <= 0) {
            printf(ERROR_MESS "ERROR IN MASTER SECRET DERIVATION\n");
            return status::ERROR;
        }

        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
        OPENSSL_cleanse(shared_secret, SHARED_SECRET_SIZE);

        return status::OK;
    }
    
};

#endif