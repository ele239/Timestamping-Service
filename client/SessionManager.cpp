#include "ClientConnection.cpp"
#include "ClientAsym.cpp"
#include "../utility/Mess.h"
#include "../utility/Hash.cpp"
#include "../utility/DTOs.h"

class SessionManager{

    private:
        
        ClientConnection* clientConn = nullptr;
        ClientAsym* clientAsym = nullptr;

        RequestMess* m = nullptr;
        ResponseMess* resp = nullptr;

        unsigned char buffer[MAX_PLAINTEXT_SIZE];

    public:

    SessionManager(){
        
        clientConn = new ClientConnection();
        clientAsym = new ClientAsym(clientConn);

        m = (RequestMess*) buffer;
        resp = (ResponseMess*) buffer;
        
    }

    ~SessionManager(){

        if(clientConn){
            delete clientConn;
            clientConn = nullptr;
        }
        if(clientAsym){
            delete clientAsym;
            clientAsym = nullptr;
        }
    }

    status createSocket(){
        return clientConn->createClientSocket();
    }

    status connectTo(const char* server_addr, short port){
        return clientConn->connectTo(server_addr, port);
    }

    void clearBuffer(){ 
        memset(buffer,0,MAX_PLAINTEXT_SIZE); 
    }

    status performHandshake(){
        return clientAsym->performHandshake();
    }

    status recvOutcome(){
        unsigned char outcome_raw;
        int ret = clientConn->decRecv(&outcome_raw);
        status outcome = (status)outcome_raw;
        return (ret > 0) ? outcome : status::ERROR;
    }

    status sendReq(request req){
        u_int8_t req_raw = (unsigned char)req;
        int ret = clientConn->encSend(&req_raw, sizeof(request));
        return (ret > 0) ? status::OK : status::ERROR;
    }


    unsigned char* readFromFile(char* path){

        FILE* file = fopen(path, "rb");
        if(!file){
            printf("ERROR: Error occurred while operning the file\n");
            return nullptr;
        }
        #ifdef COMPLETE_INFO
        printf("\n READ_FILE: File '%s' opened successfully\n", path);
        #endif

        fseek(file, 0, SEEK_END);
        long dim = ftell(file);

        if(dim < 0){
            printf("ERROR: Invalid file dimension\n");
            fclose(file);
            return nullptr;
        }

        if(dim == 0){
            printf("ERROR: File is empty\n");
            return nullptr;
        }

        fseek(file, 0, SEEK_SET);
        unsigned char* content = (unsigned char*)malloc(dim);
        if(!content){
            fclose(file);
            return nullptr;
        }

        size_t bytes_read = fread(content, 1, dim, file);
        if(bytes_read < dim){
            fclose(file);
            free(content);
            return nullptr;
        }

        #ifdef COMPLETE_INFO
        printf("READ_FILE: File %s successfully load into memory\n", path);
        #endif

        fclose(file);
        return content;
    }

    status login(){
        
        while(true){
            char username[MAX_USERNAME_LEN];
            char pwd[MAX_PWD_LEN];
            
            printf("\n-------------------------- LOGIN --------------------------\n");
            printf("Username: ");
            fgets(username, sizeof(username), stdin);
            printf("Password: ");
            fgets(pwd, sizeof(pwd), stdin);

            size_t username_len = strlen(username);
            size_t pwd_len = strlen(pwd);
            unsigned char credentials_len = username_len + pwd_len;
            username[username_len - 1] = '\0';
            pwd[pwd_len - 1] = '\0';
    
            unsigned char credentials[credentials_len];
            memcpy(credentials, username, username_len);
            memcpy(&credentials[username_len], pwd, pwd_len);

            #ifdef COMPLETE_INFO
            printf("\nLOGIN: Credentials concatenated (username || password) - total length %d bytes\n", credentials_len);
            #endif

            #ifdef COMPLETE_INFO
            printf("LOGIN: Sending credentials to the server...\n");
            #endif
            
            int bytes_sent = clientConn->encSend(credentials, credentials_len);

            if(bytes_sent < 0){
                printf("ERROR: Error while sending the credentials to the server\n");
                continue;
            }
            #ifdef COMPLETE_INFO
            printf("LOGIN: Credentials sent, waiting for server response...\n");
            #endif

            status outcome = recvOutcome();
            if(outcome == status::INVALID){
                printf("Invalid credentials\n");
                continue;
            }
            else if(outcome == status::ERROR){
                printf("ERROR: Invalid credentials inserted for %d times\n", 3);
                return status::ERROR;
            }
            else{
                printf("Authentication succeeded\n");
                break;
            }
        }
        return status::OK;
    }


    status timestamp(){
        printf("Insert the path of the document that has to be signed: ");

        char path[MAX_PATH_LEN];
        fgets(path, MAX_PATH_LEN, stdin);
        path[strlen(path)-1] = '\0';

        unsigned char* message = readFromFile(path);
        if(!message){
            printf("ERROR: Error occurred while reading from file\n");
            return status::ERROR;
        }

        m->type = request::SIGN;
        
        Hash h;
        h.calculateHash((char*)message, m->payload);

        unsigned char saved_hash[HASH_SIZE];
        memcpy(saved_hash, m->payload, HASH_SIZE);

        free(message);
        message = nullptr;
        
        #ifdef COMPLETE_INFO
        printf("\n SIGN_DOCUMENT: Hash of the document calculated successfully\n");
        #endif

        #ifdef COMPLETE_INFO
        printf("SIGN_DOCUMENT: Sending hash to server (%d bytes)...\n", 1 + HASH_SIZE);
        printf("SIGN_DOCUMENT: - Type of request (SIGN REQUEST - 1 byte)\n");
        printf("SIGN_DOCUMENT: - Hash message (%d bytes)...\n", HASH_SIZE);
        #endif
        
        ssize_t bytes_sent = clientConn->encSend((unsigned char*) m, HASH_SIZE + 1);
        if(bytes_sent < 0){
            printf("ERROR: Error occurred while sending the hash of the message\n");
            return status::ERROR;
        }

        #ifdef COMPLETE_INFO
        printf("SIGN_DOCUMENT: Waiting for signed response from server...\n");
        #endif

        ssize_t bytes_recv = clientConn->decRecv(buffer);

        if(bytes_recv < 0){
            printf("ERROR: Error occurred while receiving the message\n");
            return status::ERROR;
        }

        if(bytes_recv == 0){
            printf("ERROR: Empty message recieved by the server\n");
            return status::ERROR;
        }

        #ifdef COMPLETE_INFO
        printf("SIGN_DOCUMENT: Received %zd bytes from server\n", bytes_recv);
        printf("SIGN_DOCUMENT: - Operation outcome (1 byte)\n");
        printf("SIGN_DOCUMENT: - Hash message (%d bytes)\n", HASH_SIZE);
        printf("SIGN_DOCUMENT: - Timestamp (%d bytes)\n", TS_SIZE);
        printf("SIGN_DOCUMENT: - Signature (%d bytes)\n", SIGNATURE_SIZE);
        #endif

        SignatureMess *sig_mess = (SignatureMess*) buffer;
        status outcome = sig_mess->sts;

        if(outcome == status::INVALID){
            printf("All timestamps have been used\n");
            return status::ERROR;
        }
        else if(outcome == status::ERROR){
            printf("ERROR: Error occurred while receiving the signature\n");
            return status::ERROR;
        }

        #ifdef COMPLETE_INFO
        printf("SIGN_DOCUMENT: Proceeding to verify signature sent by the server\n");
        #endif

        unsigned char mess_to_compare[HASH_SIZE + TS_SIZE];
        memcpy(mess_to_compare, saved_hash, HASH_SIZE);
        memcpy(&mess_to_compare[HASH_SIZE], sig_mess->timestamp, TS_SIZE);
        
        outcome = clientAsym->verifySignature(clientAsym->getSignPubKey(), mess_to_compare, HASH_SIZE + TS_SIZE, sig_mess->signature);
        if(outcome == status::INVALID){
            printf("ERROR: Invalid signature\n");
            return status::ERROR;
        }
        else if(outcome == status::ERROR){
            printf("ERROR: Error occurred during signature verification\n");
            return status::ERROR;
        }
        
        printf("Signature created and successfully verified\n");
        return status::OK;
    }


    status balance(){

        #ifdef COMPLETE_INFO
        printf("\n BALANCE: Sending balance request to the server...\n");
        #endif

        status outcome = sendReq(request::BALANCE);
        if(outcome == status::ERROR){
            printf("ERROR: Error while sending the balance request to the server\n");
            return status::ERROR;
        }
        #ifdef COMPLETE_INFO
        printf("BALANCE: request correctly sent to the server\n");
        #endif

        #ifdef COMPLETE_INFO
        printf("BALANCE: Waiting for server response ...\n");
        #endif
        
        ssize_t bytes_recv = clientConn->decRecv(buffer);
        if(bytes_recv < 0){
            printf("ERROR: Error occurred while recieving the balance\n");
            return status::ERROR;
        }
        #ifdef COMPLETE_INFO
        printf("BALANCE: Received %zd bytes from server\n", bytes_recv);
        printf("BALANCE: - Number of timestamps already consumed (%ld bytes)\n", sizeof(int));
        printf("BALANCE: - Number of timestampsthe user can still request (%ld bytes)\n", sizeof(int));
        #endif

        ResponseMess* mess = (ResponseMess*) buffer;

        if(mess->sts == status::ERROR){
            printf("ERROR: Error occurred while calculating the balance\n");
            return status::ERROR;
        }

        TimestampInfo t;
        memcpy(&t, mess->payload, sizeof(t));
        #ifdef COMPLETE_INFO
        printf("BALANCE: Successfully parsed TimestampInfo from payload\n");
        #endif


        printf("Timestamps already consumed: %d\n", t.timestamps_remaining);
        printf("Timestamps that can still be requested: %d\n", t.timestamps_consumed);

        return status::OK;
    }

};