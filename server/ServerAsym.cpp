#ifndef SERVER_ASYM
#define SERVER_ASYM

#include "../utility/CryptoAsym.cpp"
#include "ServerConnection.cpp"
#include "../utility/Mess.h"

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

    EVP_PKEY * getSignPrivKey(){
        return sign_privkey;
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

        printf("\n" COLOR_YELLOW "SERVER HANDSHAKE BEGIN\n" COLOR_RESET);

        const int MAX_MESS_SIZE = max(sizeof(ClientHello),sizeof(ServerHello));

        Conversation conversation;

        unsigned char buffer[MAX_MESS_SIZE];

        ClientHello* c_hello = (ClientHello*) buffer;
        ServerHello* s_hello = (ServerHello*) buffer;

        status outcome;

        printf(YELLOW("HANDSHAKE") "Waiting to receive Client Hello...\n");

        
        ssize_t byte_counter = s_conn->recvMess((unsigned char*)c_hello,sizeof(ClientHello));

        printf(YELLOW("HANDSHAKE") "Client Hello Received\n");
        printf(FORMAT("ClientHello") "[ C_NONCE (%d) | C_EPH_PUB_KEY(%d) ] -> %zu bytes\n", NONCE_SIZE, EPH_KEY_SIZE, sizeof(ClientHello));

        printf(YELLOW("HANDSHAKE") "Received %ld bytes\n",byte_counter);

        if(byte_counter == 0){
            printf(ERROR_MESS "CLOSED SOCKET\n");
            return status::ERROR;
        }

        if(byte_counter < 0){
            printf(ERROR_MESS "RECV ERROR\n");
            return status::ERROR;
        }

        memcpy(conversation.c_nonce, c_hello->nonce, NONCE_SIZE);
        memcpy(conversation.c_eph_key_raw, c_hello->eph_key_raw, EPH_KEY_SIZE);

        EVP_PKEY* ek_client = nullptr;

        outcome = rebuildEphemeralKey(c_hello->eph_key_raw, &ek_client);

        printf(YELLOW("HANDSHAKE") "Client ephemeral public key rebuilt successfully\n");

        if(outcome == status::ERROR){
            printf(ERROR_MESS "ERROR REBUILDING EPHEMERAL KEY!\n");
            return outcome;
        }

        EVP_PKEY* ek_server = generateEphemeralKey();
        printf(YELLOW("HANDSHAKE") "Server ephemeral key pair generated\n");

        if(!ek_server){
            printf(ERROR_MESS "EPHIMERAL KEY GENERATION FAILURE!\n");
            return status::ERROR;
        }

        if(!s_conn->randomBytesGenerator(s_hello->nonce,NONCE_SIZE)){
            printf(ERROR_MESS "RandomBytesGenerator FAILURE\n");
            return status::ERROR;
        }

        printf(YELLOW("HANDSHAKE") "Server nonce Generated\n");

        outcome = getRawEphemeralKey(ek_server, s_hello->eph_key_raw);

        if(outcome == status::ERROR){
            printf(ERROR_MESS "ERROR IN RAW EPHEMERAL KEY!\n");
            return outcome;
        }

        memcpy(conversation.s_nonce, s_hello->nonce, NONCE_SIZE);
        memcpy(conversation.s_eph_key_raw, s_hello->eph_key_raw, EPH_KEY_SIZE);


        generateSignature(handshake_privkey , (unsigned char*)&conversation , sizeof(Conversation), s_hello->signature);

        printf(YELLOW("HANDSHAKE") "Signed the entire conversation\n");

        printf(YELLOW("HANDSHAKE") "Sending Server Hello...\n");
        printf(FORMAT("ServerHello") "[ NONCE (%d) | S_EPH_PUB_KEY (%d) | SIGNATURE (%d) ] -> %d total bytes\n", NONCE_SIZE, EPH_KEY_SIZE, SIGNATURE_SIZE, NONCE_SIZE + EPH_KEY_SIZE + SIGNATURE_SIZE);

        byte_counter = s_conn->sendMess((unsigned char*)s_hello, sizeof(ServerHello));

        #ifdef COMPLETE_INFO
            printf(YELLOW("HANDSHAKE") "Calculating shared secret...\n");
        #endif

        outcome = calculateSharedSecret(ek_server, ek_client, buffer);

        if(outcome == status::ERROR){
            printf(ERROR_MESS "ERROR IN SHARED SECRET GENERATION!\n");
            return outcome;
        }

        #ifdef COMPLETE_INFO
            printf(YELLOW("HANDSHAKE") "Shared secret obtained\n");
        #endif


        unsigned char symmetric_key[AES_KEY_SIZE];
        unsigned char* nonces = (unsigned char*)&conversation;

        #ifdef COMPLETE_INFO
            printf(YELLOW("HANDSHAKE") "Deriving symmetric Session Key...\n");
        #endif
        outcome = getSessionKey(buffer, symmetric_key, nonces);
        
        if(outcome == status::ERROR){
            printf(ERROR_MESS "Error in generating the session key\n");
            return outcome;
        }
        
        #ifdef COMPLETE_INFO
        printf(YELLOW("HANDSHAKE") "Session Key correctly generated\n");
        printf(YELLOW("HANDSHAKE") "Initializing Symmetric Cipher\n\n");
        #endif
        
        s_conn->symCipherInit(symmetric_key);

        return status::OK;
    }


};

#endif