#ifndef CLIENT_ASYM
#define CLIENT_ASYM

#include "../utility/CryptoAsym.cpp"
#include "ClientConnection.cpp"


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

        status verifySignature(EVP_PKEY *pub_key, const unsigned char *msg, size_t msg_len, const unsigned char *signature) {
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) return status::ERROR;

            if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pub_key) != 1) {
                EVP_MD_CTX_free(mdctx);
                return status::ERROR;
            }

            int ret = EVP_DigestVerify(mdctx, signature, SIGNATURE_SIZE , msg, msg_len);
            
            EVP_MD_CTX_free(mdctx);
            
            status outcome;

            switch (ret) // 1 valid, 0 not valid, < 0 for errors
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

            return outcome;
        }

        status performHandshake(){

            const int MAX_MESS_SIZE = NONCE_SIZE + EPH_KEY_SIZE + SIGNATURE_SIZE;

            EVP_PKEY* ek_client = generateEphemeralKey(); 
            
            unsigned char message_to_send[NONCE_SIZE + EPH_KEY_SIZE];
            unsigned char* c_nonce = message_to_send;  
            unsigned char* ek_client_raw = &message_to_send[NONCE_SIZE];
            
            status conversion = getRawEphimeralKey(ek_client, ek_client_raw); 

            if(conversion == status::ERROR){
                printf("Error in generating raw ephimeral key\n");
                return status::ERROR;
            }
            c_conn->randomBytesGenerator(c_nonce, NONCE_SIZE);

            ssize_t byte_sent = c_conn->sendMess(message_to_send, NONCE_SIZE + EPH_KEY_SIZE);
            if(byte_sent < 0){
                printf("Error while sending the ephimeral key\n");
                return status::ERROR;
            }

            unsigned char buffer[MAX_MESS_SIZE];
            
            status outcome;
            ssize_t received = c_conn->recvMess(buffer, MAX_MESS_SIZE);
        
            printf("PH: Ricevuti %ld byte\n",received);

            if(received == 0){
                printf("PH: CLOSED SOCKET\n");
                return status::ERROR;
            }

            unsigned char message_to_verify[NONCE_SIZE*2 + EPH_KEY_SIZE*2];
            unsigned char* ek_server_raw = &buffer[NONCE_SIZE]; 
            
            unsigned char* client_nonce = message_to_verify;
            unsigned char* server_nonce = &message_to_verify[NONCE_SIZE];
            unsigned char* c_eph_key = &message_to_verify[NONCE_SIZE*2];
            unsigned char* s_eph_key = &message_to_verify[NONCE_SIZE*2 + EPH_KEY_SIZE];
            
            memcpy(client_nonce, c_nonce, NONCE_SIZE);
            memcpy(server_nonce, buffer, NONCE_SIZE);
            memcpy(c_eph_key, ek_client_raw, EPH_KEY_SIZE);
            memcpy(s_eph_key, ek_server_raw, EPH_KEY_SIZE);
            
            
            unsigned char* signature = &buffer[NONCE_SIZE + EPH_KEY_SIZE];
            
            outcome = verifySignature(s_handshake_pubkey, message_to_verify, NONCE_SIZE*2 + EPH_KEY_SIZE*2, signature);
            if(outcome == status::INVALID){
                printf("The signature is invalid.\n");
                return outcome;
            }else if(outcome == status::ERROR){
                printf("Error during signature verification\n");
                return outcome;
            }else 
                printf("Miche la firma va\n");
            
            
            EVP_PKEY* ek_server = nullptr;
            outcome = rebuildEphimeralKey(s_eph_key, &ek_server);

            if(outcome == status::ERROR){
                printf("PH: ERRRORE IN REBUILD!\n");
                return outcome;
            }
            
            unsigned char shared_secret[SHARED_SECRET_SIZE];

            outcome = calculateSharedSecret(ek_client, ek_server, shared_secret);

            if(outcome == status::ERROR){
                printf("PH: Error in creating the shared secret!\n");
                return outcome;
            }
            printf("SHARED SECRET OBTAINED\n");


            unsigned char* nonces = message_to_verify;

            unsigned char symmetric_key[AES_KEY_SIZE];
            outcome = getSessionKey(shared_secret, symmetric_key, nonces); 

            if(outcome == status::ERROR){
                printf("PH: ERRORE IN GET SESSION KEY!\n");
                return outcome;
            }

            c_conn->symCipherInit(symmetric_key);
            
            printf("Session Key Extracted\n");
            return status::OK;
        }
};

#endif