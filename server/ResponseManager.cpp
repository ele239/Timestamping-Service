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

    void temp_stampa(const char* buffer, int len){
    for(int i = 0; i < len; i++){
            char c = buffer[i];
            if(c == '\n')
                cout<<"\\n";
            else
            if(c == '\r')
                cout<<"\\r";
            else            
            if(c == '\0')
                cout<<"\\0";
            else
            cout<<c;
        }
        cout <<endl;
    }

    status authenticationAttempt(){

        ssize_t bytes_counter = svConn->decRecv(buffer);

        if(bytes_counter <= 0){
            printf("ERROR OCCURRED OR SOCKET CLOSED. ABORTING...\n");
            return status::ERROR;
        }

        char* username = (char*)buffer;
        int password_pos;

        if(!validString(username, MAX_USERNAME_LEN, &password_pos)){
            return status::INVALID;
        }

        char* password = (char*)&buffer[password_pos];
        temp_stampa(password,13);
        printf("%.30s\n",password);
        if(!validString(password, MAX_PWD_LEN))
            return status::INVALID;
        

        if(uinfo->checkCredentials(username,password)){
            printf("MATCH FOUND\n");
            client_username = username;
            client_id = uinfo->findUser(client_username);
            clearBuffer();
            return status::OK;
        }else
            return status::INVALID;
    }

    status sendBalance(){

        printf("Balance request received. Providing response...\n");
        TimestampInfo timestamps = uinfo->getTimestamps(client_id);

        printf("Forming message...\n");
        resp->type = status::OK;

        // htonl

        memcpy(resp->payload, &timestamps, sizeof(timestamps));

        const unsigned int PAYLOAD_LEN = 1 + sizeof(timestamps);

        printf("Message formed.\n");

        ssize_t ret = svConn->encSend((unsigned char*)resp, PAYLOAD_LEN);

        printf("Message sent\n");
        return (ret == PAYLOAD_LEN + IV_SIZE + TAG_SIZE) ? status::OK : status::ERROR;
    }

    status signDoc(){
        return status::OK;
    }

    status manageRequests(){
        
        printf("\nAwaiting for user request\n");

        ssize_t bytes_counter = svConn->decRecv((unsigned char*)m);

        if(bytes_counter <= 0){
            printf("ERROR OCCURRED OR SOCKET CLOSED. ABORTING...\n");
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
            printf("Invalid request received. Aborting...\n");
            return status::ERROR;
            break;
        }
    }
};