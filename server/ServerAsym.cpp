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

    ServerAsym(){
        sign_pubkey = loadPublicKey(SERVER_SIGN_PUB);
        handshake_pubkey = loadPublicKey(SERVER_HANDSHAKE_PUB);
        
        sign_privkey = loadPrivateKey(SERVER_SIGN_PRIV);
        handshake_privkey = loadPrivateKey(SERVER_HANDSHAKE_PRIV);
    }

    ServerAsym(const ServerAsym& other, ServerConnection* server_connection){
            sign_privkey = other.sign_privkey;
            sign_pubkey = other.sign_pubkey;
            handshake_privkey = other.handshake_privkey;
            handshake_pubkey = other.handshake_pubkey;
            s_conn = server_connection;
    }

    ~ServerAsym(){
        if(!s_conn){
            s_conn = nullptr;
            EVP_PKEY_free(sign_privkey);
            EVP_PKEY_free(sign_pubkey);
            EVP_PKEY_free(handshake_privkey);
            EVP_PKEY_free(handshake_pubkey);
        }
    }


    status generateSignature(EVP_PKEY* sign_key,const unsigned char *message, size_t message_len, unsigned char *signature) {
        
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) 
            return status::ERROR;


        if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, sign_key) != 1) {
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

    status performHandshake(){

        const int CONVERSATION_SIZE = NONCE_SIZE * 2 + EPH_KEY_SIZE * 2;
        const int MAX_MESS_SIZE = NONCE_SIZE + EPH_KEY_SIZE + SIGNATURE_SIZE;

        unsigned char conversation[CONVERSATION_SIZE];

        unsigned char* nonces = conversation; // hashtag readability
        unsigned char* client_nonce = conversation;
        unsigned char* server_nonce = client_nonce + NONCE_SIZE;

        unsigned char* ek_client_raw = server_nonce + NONCE_SIZE;
        unsigned char* ek_server_raw = ek_client_raw + EPH_KEY_SIZE;
        
        unsigned char buffer[MAX_MESS_SIZE];

        status outcome;

        ssize_t byte_counter = s_conn->recvMess(buffer,NONCE_SIZE + EPH_KEY_SIZE);

        printf("PH: Received %ld bytes\n",byte_counter);

        if(byte_counter == 0){
            printf("PH: CLOSED SOCKET\n");
            return status::ERROR;
        }

        if(byte_counter < 0){
            printf("PH: RECV ERROR\n");
            return status::ERROR;
        }

        memcpy(conversation, buffer, NONCE_SIZE);
        memcpy(ek_client_raw, buffer + NONCE_SIZE, EPH_KEY_SIZE);

        EVP_PKEY* ek_client = nullptr;

        outcome = rebuildEphimeralKey(ek_client_raw, &ek_client);


        if(outcome == status::ERROR){
            printf("PH: ERROR IN REBUILD!\n");
            return outcome;
        }

        EVP_PKEY* ek_server = generateEphemeralKey();

        if(!ek_server){
            printf("PH: ERROR IN GENERATE!\n");
            return status::ERROR;
        }

        if(!s_conn->randomBytesGenerator(buffer,NONCE_SIZE)){
            printf("PH: RandomBytesGenerator FAILURE\n");
            return status::ERROR;
        }

        printf("Nonce Generated\n");

        outcome = getRawEphimeralKey(ek_server, ek_server_raw);

        if(outcome == status::ERROR){
            printf("PH: ERROR IN RAW EK!\n");
            return outcome;
        }

        memcpy(server_nonce, buffer, NONCE_SIZE);
        memcpy(buffer + NONCE_SIZE, ek_server_raw, EPH_KEY_SIZE);


        generateSignature(handshake_privkey ,conversation , CONVERSATION_SIZE, buffer + NONCE_SIZE + EPH_KEY_SIZE);

        printf("SIGNATURE GENERATED\n");

        byte_counter = s_conn->sendMess(buffer, MAX_MESS_SIZE);
        printf("Sent %ld bytes\n",byte_counter);

        outcome = calculateSharedSecret(ek_server, ek_client, buffer);

        if(outcome == status::ERROR){
            printf("PH: ERRORE IN SHARED SECRET!\n");
            return outcome;
        }

        printf("SHARED SECRET OBTAINED\n");

        printf("SHARED SECRET: ");

        unsigned char symmetric_key[AES_KEY_SIZE];
        outcome = getSessionKey(buffer, symmetric_key, nonces);
        
        if(outcome == status::ERROR){
            printf("PH: ERRORE IN GET SESSION KEY!\n");
            return outcome;
        }

        s_conn->symCipherInit(symmetric_key);
        
        printf("Session Key Extracted\n");

        return status::OK;
    }


};

#endif