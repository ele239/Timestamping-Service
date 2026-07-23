#include "../include/const.h"
#include "../utility/CryptoSym.cpp"

class Connection{

protected:
    int sk;
    sockaddr_in socket_info;

    CryptoSym * sym_cipher = nullptr;

    status createSocket(){
        sk = socket(AF_INET, SOCK_STREAM, 0);
        if(sk < 0){
            return status::ERROR;
        }else
            return status::OK;
    }

    ~Connection(){
        close(sk);
        if(sym_cipher){
            delete sym_cipher; 
            sym_cipher = nullptr;
        }
    }

public:

    void symCipherInit(unsigned char* key){
        if(sym_cipher){
            delete sym_cipher;
            sym_cipher = nullptr;
        }
        sym_cipher = new CryptoSym(key);
    }

    ssize_t sendMess(const unsigned char *buf, size_t len){
        return send(sk, buf, len, MSG_NOSIGNAL);
    }

    ssize_t recvMess(unsigned char *buf, size_t len){
        return recv(sk, (void*)buf, len, 0);
    }

    bool randomBytesGenerator(unsigned char* buffer, int length) {
        
        if (RAND_bytes(buffer, length) != 1)
            return false; 
        
        return true;
    }

    ssize_t encSend(const unsigned char* mess, int mess_len){
        if(!sym_cipher){
            printf(ERROR_MESS "CAN'T ENCRYPT, THE CIPHER IS NOT INITIALIZED!\n");
            return -1;
        }
        
        if(mess_len == 0)
            return 0;

        if(!mess || mess_len > MAX_PLAINTEXT_SIZE || mess_len < 0){
            printf(ERROR_MESS "CAN'T ENCRYPT, INVALID INPUT PARAMETERS!\n");
            return -1;
        }
        
        int payload_size = 0;

        unsigned char payload_buffer[MAX_CIPHERTEXT_SIZE];

        unsigned char* iv = payload_buffer; // first 16 bytes are for iv
        unsigned char* ciphertext = &payload_buffer[IV_SIZE]; // after iv comes the encrypted message
        unsigned char* tag = &payload_buffer[IV_SIZE + mess_len]; // append the tag

        if(!randomBytesGenerator(iv,IV_SIZE))
            return -1;

        if(sym_cipher->encrypt(mess, mess_len, iv, tag, ciphertext, &payload_size) != status::OK){
            return -1;
        }

        return sendMess(payload_buffer, IV_SIZE + payload_size + TAG_SIZE);
    }

    ssize_t decRecv(unsigned char* buffer){
        if(!sym_cipher){
            printf(ERROR_MESS "CAN'T DECRYPT, THE CIPHER IS NOT INITIALIZED!\n");
            return -1;
        }

        if(!buffer){
            printf(ERROR_MESS "CAN'T DECRYPT, OUTPUT BUFFER IS NULLPTR\n");
            return -1;
        }
        
        unsigned char recv_buffer[MAX_CIPHERTEXT_SIZE];
        
        int num_bytes_rec = recvMess(recv_buffer, MAX_CIPHERTEXT_SIZE);

        if(num_bytes_rec == 0){ //socket closure
            printf(ERROR_MESS "SOCKET WAS CLOSED\n");
            return 0;
        }

        if(num_bytes_rec == -1){
            printf(ERROR_MESS "CAN'T DECRYPT, ERROR OCCURRED WHILE RECEIVING THE MESSAGE\n");
            return -1;
        }
        
        int payload_len = num_bytes_rec - IV_SIZE - TAG_SIZE;
        
        if(payload_len < 1){
            printf(ERROR_MESS "CAN'T DECRYPT, PAYLOAD IS MISSING\n");
            return -1;
        }

        int plain_len;

        unsigned char* iv = recv_buffer;
        unsigned char* payload = &recv_buffer[IV_SIZE];
        unsigned char* tag = &recv_buffer[IV_SIZE + payload_len];

        status outcome = sym_cipher->decrypt(payload, payload_len, iv, tag, buffer, &plain_len); 
        
        if(outcome == status::ERROR){
            printf(WARNING_MESS "DECRYPTION FAILED\n");
            return -1;
        }

        return payload_len;
    }

};