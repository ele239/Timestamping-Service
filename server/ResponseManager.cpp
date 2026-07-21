#include "ServerConnection.cpp"
#include "UserInfoManager.cpp"
#include "../utility/Mess.h"

class ResponseManager{

    private:
        unsigned int client_id;
        UserInfoManager* uinfo = nullptr;
        ServerConnection* svConn = nullptr;
        RequestMess* m = nullptr;
        ResponseMess* resp = nullptr;

    public:

    ResponseManager(unsigned int id, UserInfoManager* user_mng, ServerConnection* server_conn, unsigned char* buffer){
        client_id = id;
        uinfo = user_mng;
        svConn = server_conn;
        m = (RequestMess*) buffer;
        resp = (ResponseMess*) buffer;
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

    status manageResponse(){
        
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