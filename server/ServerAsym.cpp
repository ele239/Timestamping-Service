#ifndef SERVER_ASYM
#define SERVER_ASYM

#include "../utility/CryptoAsym.cpp"
#include "ServerConnection.cpp"

class ServerAsym : public CryptoAsym{
    
    private:

    ServerConnection* s_conn = nullptr;

    EVP_PKEY* sign_pubkey = nullptr;
    EVP_PKEY* sign_privkey = nullptr;

    EVP_PKEY* handshake_pubkey = nullptr;
    EVP_PKEY* handshake_privkey = nullptr;

    public:

    ServerAsym(ServerConnection* server_connection){
        
        s_conn = server_connection;

        sign_pubkey = loadPublicKey(SERVER_SIGN_PUB);
        handshake_pubkey = loadPublicKey(SERVER_HANDSHAKE_PUB);
        
        sign_privkey = loadPrivateKey(SERVER_SIGN_PRIV);
        handshake_privkey = loadPrivateKey(SERVER_HANDSHAKE_PRIV);
    }

    ~ServerAsym(){
        s_conn = nullptr;
        EVP_PKEY_free(sign_privkey);
        EVP_PKEY_free(sign_pubkey);
        EVP_PKEY_free(handshake_privkey);
        EVP_PKEY_free(handshake_pubkey);
    }


    status sign_ephemeral_key(const unsigned char *message, size_t message_len, unsigned char *signature) {
        
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) 
            return status::ERROR;


        if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, sign_privkey) != 1) {
            EVP_MD_CTX_free(ctx);
            return status::ERROR;
        }

        size_t signature_size = SIGNATURE_SIZE;
        if (EVP_DigestSign(ctx, NULL, &signature_size, message, message_len) != 1) {
            EVP_MD_CTX_free(ctx);
            return status::ERROR;
        }

        if (EVP_DigestSign(ctx, signature, &signature_size, message, message_len) != 1) {
            EVP_MD_CTX_free(ctx);
            return status::ERROR;
        }

        EVP_MD_CTX_free(ctx);
        return status::OK;
    }

    status performHandshake(unsigned char* symmetric_key){

        unsigned char buffer[100];
        status outcome;

        ssize_t received = s_conn->recvMess(buffer,100);
        
        printf("PH: Ricevuti %ld byte\n",received);

        if(received == 0)
            return status::ERROR;
        
        EVP_PKEY* ek_client = nullptr;

        outcome = rebuildEphimeralKey(buffer, &ek_client);

        if(outcome == status::ERROR){
            printf("PH: ERRRORE IN REBUILD!\n");
            return outcome;
        }

        EVP_PKEY* ek_server = generateEphemeralKey();

        if(!ek_server){
            printf("PH: ERRRORE IN generate!\n");
            return status::ERROR;
        }

        outcome = getRawEphimeralKey(ek_server, buffer);

        if(outcome == status::ERROR){
            printf("PH: ERRRORE IN RAW EK!\n");
            return outcome;
        }
        
        int a = s_conn->sendMess(buffer,EPH_KEY_SIZE);
        printf("inviati %d byte\n",a);

                unsigned char *merduffer = new unsigned char[100];


        outcome = calculateSharedSecret(ek_server,ek_client,merduffer);

        printf("CALCOLATO LO SHARED SECRET\n");
        if(outcome == status::ERROR){
            printf("PH: ERRORE IN SHARED SECRET!\n");
            return outcome;
        }

        printf("ESTRAZIONE DELLA SESSION KEY\n");
        outcome = getSessionKey(merduffer, symmetric_key);
        printf("MERDA ESTRATTA\n");
        if(outcome == status::ERROR){
            printf("PH: ERRORE IN GET SESSION KEY!\n");
            return outcome;
        }

        return status::OK;
    }


};

#endif