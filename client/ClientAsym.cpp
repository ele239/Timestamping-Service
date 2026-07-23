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
                printf(ERROR_MESS "CAN'T VERIFY SIGNATUE, EVP_MD_CTX_new() failed\n");
                #endif

                return status::ERROR;
            }

            if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pub_key) != 1) {
                #ifdef COMPLETE_INFO
                printf(ERROR_MESS "CAN'T VERIFY SIGNATUE, EVP_DigestVerifyInit() failed\n");
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

            printf("\n" COLOR_YELLOW "CLIENT HANDSHAKE BEGIN\n" COLOR_RESET);

            const int MAX_MESS_SIZE = max(sizeof(ClientHello),sizeof(ServerHello));

            Conversation conv;

            unsigned char buffer[MAX_MESS_SIZE];

            ClientHello* cl_hello = (ClientHello*) buffer;
            ServerHello* sv_hello = (ServerHello*) buffer;
            
            EVP_PKEY* ek_client = generateEphemeralKey(); 

            if(!ek_client){
                printf(ERROR_MESS "EPHIMERAL KEY GENERATION FAILURE!\n");
                return status::ERROR;
            }

            #ifdef COMPLETE_INFO
            printf(YELLOW("HANDSHAKE") "Client ephemeral key pair generated\n");
            #endif

            status conversion = getRawEphemeralKey(ek_client, cl_hello->eph_key_raw); 

            if(conversion == status::ERROR){
                printf(ERROR_MESS "Error in generating raw ephemeral key\n");
                return status::ERROR;
            }
            
            c_conn->randomBytesGenerator(cl_hello->nonce, NONCE_SIZE);
            #ifdef COMPLETE_INFO
                printf(YELLOW("HANDSHAKE") "Client nonce generated (%d bytes)\n", NONCE_SIZE);
                printf(YELLOW("HANDSHAKE") "Sending Client Hello...\n");
            
                #ifdef MESSAGE_FORMAT
                    printf(FORMAT("ClientHello") "[ C_NONCE (%d) | C_EPH_PUB_KEY(%d) ] -> %zu bytes\n", NONCE_SIZE, EPH_KEY_SIZE, sizeof(ClientHello));
                #endif
            #endif

            ssize_t byte_sent = c_conn->sendMess((unsigned char*)cl_hello, sizeof(ClientHello));
            if(byte_sent < 0){
                printf(ERROR_MESS "Error while sending the Client Hello Message\n");
                return status::ERROR;
            }

            #ifdef COMPLETE_INFO
            printf(YELLOW("HANDSHAKE") "Client Hello message sent successfully\n");
            #endif

            memcpy(conv.c_nonce, cl_hello->nonce, NONCE_SIZE);
            memcpy(conv.c_eph_key_raw, cl_hello->eph_key_raw, EPH_KEY_SIZE);

            #ifdef COMPLETE_INFO
            printf(YELLOW("HANDSHAKE") "Waiting to receive Server Hello...\n");
            #endif
            
            ssize_t received = c_conn->recvMess((unsigned char*)sv_hello, sizeof(ServerHello));
            
            if(received == 0){
                printf(ERROR_MESS "Error in receiving the message. Closing the socket...\n");
                return status::ERROR;
            }

            #ifdef COMPLETE_INFO
                printf(YELLOW("HANDSHAKE") "ServerHello received\n");
                #ifdef MESSAGE_FORMAT    
                    printf(FORMAT("ServerHello") "[ NONCE (%d) | S_EPH_PUB_KEY (%d) | SIGNATURE (%d) ] -> %d total bytes\n", NONCE_SIZE, EPH_KEY_SIZE, SIGNATURE_SIZE, NONCE_SIZE + EPH_KEY_SIZE + SIGNATURE_SIZE);
                    printf(YELLOW("HANDSHAKE") "Received %ld bytes\n",received);
                    #endif
            #endif
            
            memcpy(conv.s_nonce, sv_hello->nonce, NONCE_SIZE);
            memcpy(conv.s_eph_key_raw, sv_hello->eph_key_raw, EPH_KEY_SIZE);
            
            status outcome;
            outcome = verifySignature(s_handshake_pubkey, (unsigned char*)&conv, sizeof(Conversation), sv_hello->signature);
            
            if(outcome == status::INVALID){
                printf(ERROR_MESS "Server Hello Signature is INVALID!\n");
                return outcome;

            }else if(outcome == status::ERROR){
                printf(ERROR_MESS "Error occurred during signature verification\n");
                return outcome;
                
            }
            #ifdef COMPLETE_INFO
            printf(YELLOW("HANDSHAKE") "Server Hello Signature Verified\n");
            #endif
            
            EVP_PKEY* ek_server = nullptr;
            outcome = rebuildEphemeralKey(conv.s_eph_key_raw, &ek_server);

            if(outcome == status::ERROR){
                printf(ERROR_MESS "Error in rebuilding the ephemeral key\n");
                return outcome;
            }

            #ifdef COMPLETE_INFO
            printf(YELLOW("HANDSHAKE") "Server ephemeral public key rebuilt successfully\n");
            #endif
            
            unsigned char shared_secret[SHARED_SECRET_SIZE];

            #ifdef COMPLETE_INFO
            printf(YELLOW("HANDSHAKE") "Calculating shared secret...\n");
            #endif

            outcome = calculateSharedSecret(ek_client, ek_server, shared_secret);

            if(outcome == status::ERROR){
                printf(ERROR_MESS "Error in creating the shared secret!\n");
                return outcome;
            }
            #ifdef COMPLETE_INFO
            printf(YELLOW("HANDSHAKE") "Shared secret obtained\n");
            #endif

            unsigned char* nonces = (unsigned char*)&conv;

            unsigned char symmetric_key[AES_KEY_SIZE];

            #ifdef COMPLETE_INFO
            printf(YELLOW("HANDSHAKE") "Deriving symmetric Session Key...\n");
            #endif
            outcome = getSessionKey(shared_secret, symmetric_key, nonces); 

            if(outcome == status::ERROR){
                printf(ERROR_MESS "Error in generating the session key\n");
                return outcome;
            }

            #ifdef COMPLETE_INFO
            printf(YELLOW("HANDSHAKE") "Session Key correctly generated\n");
            printf(YELLOW("HANDSHAKE") "Initializing Symmetric Cipher\n\n");
            #endif
            
            c_conn->symCipherInit(symmetric_key);
            
            return status::OK;
        }
};

#endif