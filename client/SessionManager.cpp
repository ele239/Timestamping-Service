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


    unsigned char* readFromFile(const char* path, unsigned int* len){

        FILE* file = fopen(path, "rb");
        if(!file){
            printf("ERROR: Error occurred while operning the file\n");
            return nullptr;
        }
        #ifdef COMPLETE_INFO
        printf("\nREAD_FILE: File '%s' opened successfully\n", path);
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
        
        *len = (unsigned int)dim;
        fseek(file, 0, SEEK_SET);
        unsigned char* content = (unsigned char*)malloc(dim);
        if(!content){
            fclose(file);
            return nullptr;
        }

        size_t bytes_read = fread(content, 1, dim, file);
        if((int)bytes_read < dim){
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
            printf("ERROR: Error occurred while receiving the balance\n");
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

    status storeSignature(unsigned char* signature){
        
        FILE* file = fopen(SIGNATURE_FILE_PATH, "ab");
        if(!file){
            printf("ERROR: Error while opening the signature file\n");
            return status::ERROR;
        }

        size_t len = HASH_SIZE + TS_SIZE + SIGNATURE_SIZE;

        size_t bytes_written = fwrite(signature, 1, len, file);
        if(bytes_written < len){
            printf("ERROR: Error writing to signature file\n");
            fclose(file);
            return status::ERROR;
        }
        
        unsigned char end_string = '\n';
        bytes_written = fwrite(&end_string, 1, 1, file);
        if(bytes_written < 1){
            printf("ERROR: Error writing to signature file\n");
            fclose(file);
            return status::ERROR;
        }

        fclose(file);
        return status::OK;
        
    }

    status searchSignature(unsigned char* hash, vector<unsigned char*>* signatures){
        
        FILE* file = fopen(SIGNATURE_FILE_PATH, "rb");
        if(!file){
            printf("ERROR: Error while opening the file\n");
            return status::ERROR;
        }

        int len = HASH_SIZE + TS_SIZE + SIGNATURE_SIZE;
        unsigned char* sig = new unsigned char[len + 1];

        while((int)fread(sig, 1, len + 1, file) == len + 1){
            if(!memcmp(sig, hash, HASH_SIZE)){
                unsigned char* element = new unsigned char[len];
                memcpy(element, sig, len);
                signatures->push_back(element);
            }
        }

        fclose(file);
        delete[] sig;
        return status::OK;
        
    }

    void getFilePath(char*path){
        fgets(path, MAX_PATH_LEN, stdin);
        path[strnlen(path,MAX_PATH_LEN)-1] = '\0';
    }

    status getDocumentHash(const char* path,unsigned char* dest){        

        unsigned int file_size;
        unsigned char* message = readFromFile(path, &file_size);
        if(!message){
            printf("ERROR: Error occurred while reading from file\n");
            free(message);
            return status::ERROR;
        }
        
        Hash h;
        h.calculateHash((char*)message, file_size,dest);

        free(message);

        return status::OK;
    }

    status timestamp(){
        printf("Insert the path of the document that has to be signed: ");

        char path[MAX_PATH_LEN];
        unsigned char saved_hash[HASH_SIZE];

        getFilePath(path);

        status outcome = getDocumentHash(path, saved_hash);
        if(outcome != status::OK){
            printf("ERROR: Document hashing failed\n");
            return status::ERROR;
        }

        memcpy(m->payload, saved_hash, HASH_SIZE);

        m->type = request::SIGN;
        
        #ifdef COMPLETE_INFO
        printf("\nSIGN_DOCUMENT: Hash of the document calculated successfully\n");
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
            printf("ERROR: Empty message received by the server\n");
            return status::ERROR;
        }

        #ifdef COMPLETE_INFO

        printf("SIGN_DOCUMENT: RESPONSE STRUCTURE\n");
        printf("[ STATUS (1) | HASH (%d) | TIMESTAMP (%d) | SIGNATURE (%d) ] -> %d bytes total\n",HASH_SIZE, TS_SIZE, SIGNATURE_SIZE, 1 + HASH_SIZE + TS_SIZE + SIGNATURE_SIZE);
        
        #endif

        SignatureMess *sig_mess = (SignatureMess*) buffer;
        outcome = sig_mess->sts;

        if(outcome == status::INVALID){
            printf("All timestamps have been used\n");
            return status::ERROR;
        }
        else if(outcome == status::ERROR){
            printf("ERROR: Error occurred while receiving the signature\n");
            return status::ERROR;
        }

        unsigned char verify_buffer[HASH_SIZE + TS_SIZE + SIGNATURE_SIZE];

        SignatureMess* ver_mess = (SignatureMess*)(verify_buffer - 1);
        memcpy(ver_mess->hash, saved_hash, HASH_SIZE); // We use our hash to check the signature
        memcpy(ver_mess->timestamp, sig_mess->timestamp, TS_SIZE);
        memcpy(ver_mess->signature, sig_mess->signature, SIGNATURE_SIZE);


        outcome = clientAsym->verifySignature(clientAsym->getSignPubKey(), verify_buffer , HASH_SIZE + TS_SIZE, ver_mess->signature);

        switch (outcome)
        {
        case status::OK:
            printf("SIGN_DOCUMENT: Signature Status -> OK! Timestamp: ");
            printTimestampOf(verify_buffer);
            outcome = storeSignature(verify_buffer);
            break;

        case status::INVALID:
            printf("SIGN_DOCUMENT: Signature Status -> INVALID!!!! BEWARE!\n");        
            break;

        case status::ERROR:
            printf("ERROR: An error occurred during signature verification.\n");
            break;
                
        default:
            break;
        }

        return outcome;
    }

    void printTimestampOf(unsigned char* doc){
        chrono::milliseconds ts;
        memcpy(&ts, doc + HASH_SIZE, TS_SIZE);
        
        std::chrono::system_clock::time_point tp(ts);
        
        auto tp_seconds = std::chrono::time_point_cast<std::chrono::seconds>(tp);
        auto local_time = std::chrono::zoned_time{std::chrono::current_zone(), tp_seconds};
        std::cout << std::format("{:%Y-%m-%d %H:%M:%S}", local_time) << '\n';
    }

    status verify(){
        printf("\nInsert the path of the document whose signature you want to verify: ");

        char path[MAX_PATH_LEN];
        
        getFilePath(path);

        status outcome = getDocumentHash(path, buffer);
        if(outcome != status::OK){
            printf("ERROR: Document hashing failed\n");
            return status::ERROR;
        }
        
        #ifdef COMPLETE_INFO
        printf("\nVERIFY_SIGNATURE: Hash of the document calculated successfully\n");
        #endif

        vector<unsigned char*>* doc_list = new vector<unsigned char*>(); 

        auto clearList = [=](){
            for(auto d : *doc_list)
                delete[] d;
            
            delete doc_list;
        };

        outcome = searchSignature(buffer,doc_list);

        if(outcome == status::ERROR){
            printf("ERROR: Couldn't search any signed documents\n");
            clearList();
            return status::ERROR;
        }

        if(doc_list->empty()){
            printf("WARNING: No signature linked to file %s was found!\n\n",path);
            clearList();
            return status::INVALID;
        }

        unsigned int signature_pos = HASH_SIZE + TS_SIZE;

        #ifdef COMPLETE_INFO
        printf("VERIFY_SIGNATURE: Found %ld signatures linked to document \"%s\"\n", doc_list->size(), path);
        printf("VERIFY_SIGNATURE: Proceeding to verify the signatures sent by the server\n");
        #endif

        for(auto doc : *doc_list){
    
            outcome = clientAsym->verifySignature(clientAsym->getSignPubKey(), doc, HASH_SIZE + TS_SIZE, &doc[signature_pos]);

            switch (outcome)
            {
            case status::OK:
                printf("- Signature of file \"%s\" is OK! Signature Timestamp: ", path);        
                printTimestampOf(doc);
                break;

            case status::INVALID:
                printf("- Beware! Signature of file \"%s\" is INVALID!\n", path);
                break;

            case status::ERROR:
                printf("- An error occurred during signature verification.\n");
                break;
                    
            default:
                break;
            }

        }

        clearList();
        return outcome;
    }

};