#ifndef CLIENT_ASYM
#define CLIENT_ASYM

#include "../utility/CryptoAsym.cpp"
#include "ClientConnection.cpp"
#include "../utility/Mess.h"


class ClientAsym : public CryptoAsym{

    private:
        EVP_PKEY* s_handshake_pubkey = nullptr;
        EVP_PKEY* s_sign_pubkey = nullptr;
        ClientConnection* c_conn = nullptr;

    public: 

        ClientAsym(ClientConnection* c_connection){
            s_handshake_pubkey = loadPublicKey(SERVER_HANDSHAKE_PUB);
            s_sign_pubkey = loadPublicKey(SERVER_SIGN_PUB);
            c_conn = c_connection;
        }

        ~ClientAsym(){
            c_conn = nullptr;
            EVP_PKEY_free(s_handshake_pubkey);
            EVP_PKEY_free(s_sign_pubkey);
        }

        EVP_PKEY * getSignPubKey(){
            return s_sign_pubkey;
        }

        status verifySignature(EVP_PKEY *pub_key, const unsigned char *msg, size_t msg_len, const unsigned char *signature) {

            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx){
                #ifdef COMPLETE_INFO
                printf("VERIFY_SIG: EVP_MD_CTX_new() failed\n");
                #endif

                return status::ERROR;
            }

            if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pub_key) != 1) {
                #ifdef COMPLETE_INFO
                printf("VERIFY_SIG: EVP_DigestVerifyInit() failed\n");
                #endif

                EVP_MD_CTX_free(mdctx);
                return status::ERROR;
            }

            int ret = EVP_DigestVerify(mdctx, signature, SIGNATURE_SIZE , msg, msg_len);
            
            EVP_MD_CTX_free(mdctx);
            
            status outcome;

            switch (ret) 
            {
            case 0:
                outcome = status::INVALID;
                break;
                
            case 1:
                outcome = status::OK;
                break;

            default:
                outcome = status::ERROR;
                break;
            }

            /*
            #ifdef COMPLETE_INFO
            printf("VERIFY_SIG: EVP_DigestVerify returned %d -> outcome %d\n", ret, (int)outcome);
            printf("VERIFY_SIG: (1) -> valid signature \n");
            printf("VERIFY_SIG: (0) -> invalid signature \n");
            printf("VERIFY_SIG: (< 0) -> error occurred while verifying the signature \n");
            #endif
            */

            return outcome;
        }

        status performHandshake(){

            const int MAX_MESS_SIZE = max(sizeof(ClientHello),sizeof(ServerHello));

            Conversation conv;

            unsigned char buffer[MAX_MESS_SIZE];

            ClientHello* cl_hello = (ClientHello*) buffer;
            ServerHello* sv_hello = (ServerHello*) buffer;
            
            EVP_PKEY* ek_client = generateEphemeralKey(); 
            #ifdef COMPLETE_INFO
            printf("HANDSHAKE: Ephemeral key pair generated\n");
            #endif

            status conversion = getRawEphimeralKey(ek_client, cl_hello->eph_key_raw); 

            if(conversion == status::ERROR){
                printf("ERROR: Error in generating raw ephimeral key\n");
                return status::ERROR;
            }
            
            c_conn->randomBytesGenerator(cl_hello->nonce, NONCE_SIZE);
            #ifdef COMPLETE_INFO
            printf("HANDSHAKE: Client nonce generated (%d bytes)\n", NONCE_SIZE);
            printf("HANDSHAKE: Sending ClientHello = [ C_NONCE (%d) | C_EPH_PUB_KEY(%d) ], total size=%zu bytes\n", NONCE_SIZE, EPH_KEY_SIZE, sizeof(ClientHello));
            #endif

            ssize_t byte_sent = c_conn->sendMess((unsigned char*)cl_hello, sizeof(ClientHello));
            if(byte_sent < 0){
                printf("ERROR: Error while sending the Client Hello Message\n");
                return status::ERROR;
            }

            #ifdef COMPLETE_INFO
            printf(COLOR_YELLOW "HANDSHAKE: " COLOR_RESET "Client Hello message sent successfully\n");
            #endif

            memcpy(conv.c_nonce, cl_hello->nonce, NONCE_SIZE);
            memcpy(conv.c_eph_key_raw, cl_hello->eph_key_raw, EPH_KEY_SIZE);

            #ifdef COMPLETE_INFO
            printf(COLOR_YELLOW "HANDSHAKE: " COLOR_RESET "Waiting to receive ServerHello ...\n");
            #endif
            
            ssize_t received = c_conn->recvMess((unsigned char*)sv_hello, sizeof(ServerHello));
            
            if(received == 0){
                printf(COLOR_RED "ERROR: " COLOR_RESET "Error in recieving the message. Closing the socket ...\n");
                return status::ERROR;
            }

            #ifdef COMPLETE_INFO
            printf(COLOR_YELLOW "HANDSHAKE: " COLOR_RESET "ServerHello received\n");
            printf("format = [ NONCE (%d) | S_EPH_PUB_KEY (%d) | SIGNATURE (%d) ] -> %d total bytes\n", NONCE_SIZE, EPH_KEY_SIZE, SIGNATURE_SIZE, NONCE_SIZE + EPH_KEY_SIZE + SIGNATURE_SIZE);
            #endif
            
            memcpy(conv.s_nonce, sv_hello->nonce, NONCE_SIZE);
            memcpy(conv.s_eph_key_raw, sv_hello->eph_key_raw, EPH_KEY_SIZE);
            
            status outcome;
            outcome = verifySignature(s_handshake_pubkey, (unsigned char*)&conv, sizeof(Conversation), sv_hello->signature);
            
            if(outcome == status::INVALID){
                printf(COLOR_RED "ERROR: " COLOR_RESET "Server Hello Signature is INVALID!\n");
                return outcome;

            }else if(outcome == status::ERROR){
                printf(COLOR_RED "ERROR: " COLOR_RESET "Error occurred during signature verification\n");
                return outcome;
                
            }
            #ifdef COMPLETE_INFO
            printf(COLOR_YELLOW "HANDSHAKE: " COLOR_RESET "Server Hello Signature Verified\n");
            #endif
            
            EVP_PKEY* ek_server = nullptr;
            outcome = rebuildEphimeralKey(conv.s_eph_key_raw, &ek_server);

            if(outcome == status::ERROR){
                printf(COLOR_RED "ERROR: " COLOR_RESET "Error in rebuilding the ephemeral key\n");
                return outcome;
            }

            #ifdef COMPLETE_INFO
            printf(COLOR_YELLOW "HANDSHAKE: " COLOR_RESET "Server ephemeral public key rebuilt successfully\n");
            #endif
            
            unsigned char shared_secret[SHARED_SECRET_SIZE];

            #ifdef COMPLETE_INFO
            printf(COLOR_YELLOW "HANDSHAKE: " COLOR_RESET "Calculating shared secret (SIZE: %d) via ECDH...\n", SHARED_SECRET_SIZE);
            #endif

            outcome = calculateSharedSecret(ek_client, ek_server, shared_secret);

            if(outcome == status::ERROR){
                printf(COLOR_RED "ERROR: " COLOR_RESET "Error in creating the shared secret!\n");
                return outcome;
            }
            #ifdef COMPLETE_INFO
            printf(COLOR_YELLOW "HANDSHAKE: " COLOR_RESET "Shared secret obtained\n");
            #endif

            unsigned char* nonces = (unsigned char*)&conv;

            unsigned char symmetric_key[AES_KEY_SIZE];

            #ifdef COMPLETE_INFO
            printf(COLOR_YELLOW "HANDSHAKE: " COLOR_RESET "Deriving symmetric Session Key...\n");
            #endif
            outcome = getSessionKey(shared_secret, symmetric_key, nonces); 

            if(outcome == status::ERROR){
                printf(COLOR_RED "ERROR: " COLOR_RESET "Error in generating the session key\n");
                return outcome;
            }

            c_conn->symCipherInit(symmetric_key);
            
            #ifdef COMPLETE_INFO
            printf(COLOR_YELLOW "HANDSHAKE: " COLOR_RESET "Session Key correctly generated\n");
            #endif
            return status::OK;
        }
};

#endif