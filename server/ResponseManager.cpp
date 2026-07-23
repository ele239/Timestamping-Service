#include "ServerConnection.cpp"
#include "ServerAsym.cpp"
#include "UserInfoManager.cpp"
#include "../utility/Mess.h"

class ResponseManager{

    private:

        string client_username = "";
        int client_id = -1;
    
        UserInfoManager* uinfo = nullptr;
        
        ServerConnection* svConn = nullptr;
        ServerAsym* svAsym = nullptr;

        RequestMess* m = nullptr;
        ResponseMess* resp = nullptr;

        unsigned char buffer[MAX_PLAINTEXT_SIZE];

    public:

    ResponseManager(int sock, ServerAsym& server_keys, UserInfoManager* user_mng){
        
        uinfo = user_mng;
        
        m = (RequestMess*) buffer;
        resp = (ResponseMess*) buffer;

        svConn = new ServerConnection(sock);
        svAsym = new ServerAsym(server_keys, svConn);
        
    }

    ~ResponseManager(){
        if(svConn){
            delete svConn;
            svConn = nullptr;
        }

        if(svAsym){
            delete svAsym;
            svAsym = nullptr;
        }
    }

    void clearBuffer(){ 
        memset(buffer,0,MAX_PLAINTEXT_SIZE); 
    }

    status sendStatus(status s){
        u_int8_t s_raw = (unsigned char)s;
        int ret = svConn->encSend(&s_raw, sizeof(status));
        return (ret > 0) ? status::OK : status::ERROR;
    }

    string getUsername(){
        return client_username;
    }

    status performHandshake(){
        return svAsym->performHandshake();
    }

    inline bool validString(const char* input, const int max_len, int* next_pos = nullptr){
        const unsigned char len = strnlen(input, max_len - 1);
        
        if(next_pos)
            *next_pos = len + 1;

        return (len != 0 && input[len] == '\0');
    }

    uint64_t generateTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
        
        return static_cast<uint64_t>(millis);
    }

    status authenticationAttempt(){

        ssize_t bytes_counter = svConn->decRecv(buffer);

        if(bytes_counter <= 0){
            printf(ERROR_MESS "decRecv FAILED.\n");
            return status::ERROR;
        }

        char* username = (char*)buffer;
        int password_pos;

        if(!validString(username, MAX_USERNAME_LEN, &password_pos)){
            return status::INVALID;
        }

        char* password = (char*)&buffer[password_pos];

        if(!validString(password, MAX_PWD_LEN))
            return status::INVALID;
        

        if(uinfo->checkCredentials(username,password)){
            printf("\n" AQUA("AUTH_ATTEMPT") "Match found\n\n");
            client_username = username;
            client_id = uinfo->findUser(client_username);
            clearBuffer();
            return status::OK;
        }else
            return status::INVALID;
    }

    status sendBalance(){

        printf("\n" INDIGO("SEND_BALANCE") "Balance request received. Providing response...\n");
        TimestampInfo timestamps = uinfo->getTimestamps(client_id);

        resp->sts = status::OK;

        // htonl

        memcpy(resp->payload, &timestamps, sizeof(timestamps));

        const unsigned int PAYLOAD_LEN = 1 + sizeof(timestamps);

        ssize_t ret = svConn->encSend((unsigned char*)resp, PAYLOAD_LEN);

        if(ret != IV_SIZE + PAYLOAD_LEN + TAG_SIZE){
            if(ret == 0)
                printf(ERROR_MESS "SOCKET WAS CLOSED\n");
            else
                printf(ERROR_MESS "encSend FAILED\n");
            return status::ERROR;
        }

            printf(INDIGO("SEND_BALANCE") "Timestamp balance sent.\n");

            #ifdef MESSAGE_FORMAT
                printf(FORMAT("Timestamp Balance") "[ Status (1) | Remaining (4) | Consumed (4) ] -> 9 bytes\n");
            #endif

        return status::OK;
    }

    status generateSignature(const unsigned char* data_to_sign, int data_size, unsigned char* signature){
        EVP_PKEY* sign_key = svAsym->getSignPrivKey(); 
        return svAsym->generateSignature(sign_key, data_to_sign, data_size, signature);
    }

    status signDoc(){

        printf("\n" GREEN("SIGN_DOC") "Signature request received. Providing response...\n");

        #ifdef MESSAGE_FORMAT
            printf(FORMAT("Sign Request") "[ SIGN_REQUEST (1) | HASH (%d) ] -> %d bytes\n", HASH_SIZE, 1 + HASH_SIZE);
        #endif

        SignatureMess* s_mess = (SignatureMess*) buffer;

        status outcome = uinfo->consumeTimestamp(client_id);

        if(outcome != status::OK){
            sendStatus(outcome);
            return (outcome == status::INVALID) ? status::OK : status::ERROR;
        }
        
        unsigned char unsigned_data[HASH_SIZE + TS_SIZE];
        SignatureMess* to_sign_mess = (SignatureMess*) (unsigned_data - 1);

        memcpy(to_sign_mess->hash,m->payload, HASH_SIZE);

        u_int64_t ts = generateTimestamp();
        memcpy(to_sign_mess->timestamp, &ts, sizeof(ts)); 

        outcome = generateSignature(unsigned_data, HASH_SIZE + TS_SIZE, s_mess->signature);     
        
        if(outcome != status::OK){
            printf(ERROR_MESS "AN ERROR OCCURRED DURING SIGNATURE GENERATION\n");
            sendStatus(status::ERROR);
            return status::ERROR;
        }

        memcpy(resp->payload, unsigned_data, HASH_SIZE + TS_SIZE);

        resp->sts = status::OK;

        const unsigned int PAYLOAD_SIZE = 1 + HASH_SIZE + TS_SIZE + SIGNATURE_SIZE;

        printf(GREEN("SIGN_DOC") "Sending signed document to the client\n");

        ssize_t byte_counter = svConn->encSend((unsigned char*)s_mess, PAYLOAD_SIZE);

        if(byte_counter < IV_SIZE + PAYLOAD_SIZE + TAG_SIZE){
            printf("signDoc: SEND ERROR OR SOCKET CLOSED!\n");
            return status::ERROR;
        }

        #ifdef MESSAGE_FORMAT
            printf(FORMAT("Sign Response") "[ STATUS (1) | HASH (%d) | TIMESTAMP (%d) | SIGNATURE (%d) ] -> %d bytes\n",HASH_SIZE, TS_SIZE, SIGNATURE_SIZE, 1 + HASH_SIZE + TS_SIZE + SIGNATURE_SIZE);
        #endif
        
        return status::OK;
    }

    status manageRequests(){
        
        printf("\n" SKYBLUE("SERVER_THREAD") "Awaiting for user request...\n");

        ssize_t bytes_counter = svConn->decRecv((unsigned char*)m);

        if(bytes_counter <= 0){
            printf(ERROR_MESS "decRecv FAILED\n");
            return status::ERROR;
        }

        switch (m->type)
        {
        case request::BALANCE:
            return sendBalance();
            break;

        case request::SIGN:
            return signDoc();
            break;

        default:
            printf(ERROR_MESS "Invalid request received. Aborting...\n");
            return status::ERROR;
            break;
        }
    }
};