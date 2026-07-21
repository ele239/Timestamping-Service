#include "server/ServerConnection.cpp"
#include "server/UserInfoManager.cpp"
#include "server/ServerAsym.cpp"
#include "server/ResponseManager.cpp"
#include "utility/Mess.h"

UserInfoManager uinfo;
ServerAsym Server_Asymmetric_Keys;


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

void worker(int sk){

    string client_username("");
    unsigned int client_id;

    ServerConnection svConn(sk);
    ServerAsym s_asym(Server_Asymmetric_Keys, &svConn);

    status outcome;
    ssize_t bytes_counter;

    printf(":: NEW REQUEST ::\n");

    outcome = s_asym.performHandshake();

    if(outcome != status::OK){
        printf("The handshake did not go well. Aborting the connection...\n");
        return;
    }

    printf("Handshake Performed successfully!\n");

    vector<unsigned char> vec_buffer(MAX_PLAINTEXT_SIZE);
    unsigned char* buffer = vec_buffer.data();

    auto clear_buf = [&](){ memset(buffer,0,MAX_PLAINTEXT_SIZE); };

    auto sendStatus = [&](status s){
        u_int8_t s_raw = (unsigned char)s;
        int ret = svConn.encSend(&s_raw, sizeof(status));
        return (ret > 0) ? status::OK : status::ERROR;
    };

    printf("Awaiting for User Authentication\n");

    unsigned char tries = MAX_TRIES;
    while(tries){
        printf("Tries remaining: %d\n", tries);
        bytes_counter = svConn.decRecv(buffer);

        if(bytes_counter <= 0){
            printf("ERROR OCCURRED OR SOCKET CLOSED. ABORTING...\n");
            return;
        }

        char* username = (char*)buffer;
        unsigned char username_len = strnlen(username,MAX_USERNAME_LEN);

        if(username_len == 0 || username[username_len] != '\0'){
            tries--;
            if(tries > 0)
                sendStatus(status::INVALID);
            continue;
        }

        char* password = (char*)&buffer[username_len + 1];
        unsigned char pwd_len = strnlen(password, MAX_PWD_LEN);

        if(pwd_len == 0 || password[pwd_len] != '\0'){
            tries--;
            if(tries > 0)
                sendStatus(status::INVALID);
            continue;
        }

        if(uinfo.checkCredentials(username,password)){
            printf("MATCH FOUND\n");
            client_username = username;
            client_id = uinfo.findUser(client_username);
            clear_buf();
            break;
        }

        tries--;
        if(tries > 0)
            sendStatus(status::INVALID);
    }
    if(!tries){
        printf("The user failed to authenticate. Aborting the connection...\n");
        sendStatus(status::ERROR);
        return;
    }else{
        printf("The user \"%s\" has logged in successfully.\n",client_username.data());
        sendStatus(status::OK);
    }

    ResponseManager rm(client_id, &uinfo, &svConn, buffer);

    while(true){
        
        outcome = rm.manageResponse();

        if(outcome != status::OK){
            break;
        }

    }

    printf("Connection Terminated with \"%s\". Thread exiting...\n", client_username.c_str());

}

void th_listen(short port){

    ServerConnection svConn;

    status outcome;

    int client_sock;

    printf("Creating Listen Socket...\n");

    outcome = svConn.createListenSocket(port);

    
    if(outcome == status::ERROR){
        printf("FATAL ERROR WHEN CREATING SOCKET!! QUITTING.\n");
        return;
    }

    printf("Listen Socket Created. Waiting for Connection...\n");

    while(true){
        client_sock = svConn.acceptConnection();
        if(client_sock < 0){
            printf("Unexpected outcome during accept...\n");
            continue;
        }
        printf("Connection received!\n");
        jthread work(worker, client_sock);

    }

}


int main(int argc, char* argv[]){

    in_port_t port = (argc == 1) ? DEFAULT_PORT : atoi(argv[1]);

    if(!uinfo.isValid()){
        printf("Failure in loading User Info! Aborting...\n");
        return EXIT_FAILURE;
    }

    printf("Server is turning on -> Port: %d\n",port);
    
    jthread th_listener(th_listen, port);

    return EXIT_SUCCESS;
}