#include "server/ServerConnection.cpp"
#include "server/UserInfoManager.cpp"
#include "server/ServerAsym.cpp"

UserInfoManager uinfo;
ServerAsym Server_Asymmetric_Keys;

void worker(int sk){

    string client_username("");
    int client_id;

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

    vector<unsigned char> vec_buffer(100);
    unsigned char* buffer = vec_buffer.data();

    unsigned char tries = MAX_TRIES;
    while(tries){
        bytes_counter = svConn.decRecv(buffer);
        
        if(bytes_counter <= 0){
            printf("ERROR OCCURRED OR SOCKET CLOSED. ABORTING...\n");
            return;
        }

        unsigned char username_len = buffer[0];
        unsigned char pwd_len = buffer[1];

        if(username_len >= MAX_USERNAME_LEN || pwd_len >= MAX_PWD_LEN){
            tries--;
            continue;
        }

        if(uinfo.checkCredentials()){
            break;
        }

        tries--;
    }
    if(!tries){
        printf("The user failed to authenticate. Aborting the connection...\n");
        return;
    }else
        printf("The user \"%s\" has logged in successfully.\n",);


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