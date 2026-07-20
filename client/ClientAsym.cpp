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

        status performHandshake(unsigned char* symmetric_key){

            EVP_PKEY* eph_key = generateEphemeralKey(); 
            
            unsigned char raw_key[EPH_KEY_SIZE];
            status conversion = getRawEphimeralKey(eph_key, raw_key); 

            if(conversion == status::ERROR){
                printf("Error in generating raw ephimeral key\n");
                return status::ERROR;
            }

            size_t byte_sent = c_conn->sendMess(raw_key, EPH_KEY_SIZE);
            if(byte_sent < 0){
                printf("Error while sending the ephimeral key\n");
                return status::ERROR;
            }

            unsigned char buffer[100];
            status outcome;

            ssize_t received = c_conn->recvMess(buffer,100);
            
            printf("PH: Ricevuti %ld byte\n",received);

            if(received == 0)
                return status::ERROR;
            
            EVP_PKEY* ek_server = nullptr;

            outcome = rebuildEphimeralKey(buffer, &ek_server);

            if(outcome == status::ERROR){
                printf("PH: ERRRORE IN REBUILD!\n");
                return outcome;
            }
            unsigned char *merduffer = new unsigned char[100];

            outcome = calculateSharedSecret(eph_key, ek_server, merduffer);

            if(outcome == status::ERROR){
                printf("PH: Error in creating the shared secret!\n");
                return outcome;
            }

            getSessionKey(merduffer,symmetric_key);
            return status::OK;
        }
};

#endif