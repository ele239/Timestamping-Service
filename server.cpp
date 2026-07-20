#include "server/ServerConnection.cpp"
#include "server/UserInfoManager.cpp"
#include "server/ServerAsym.cpp"

UserInfoManager uinfo;

void worker(int sk){

    string client_username("");

    ServerConnection svConn(sk);
    printf("Miche funziona\n");

    printf(":: INIZIO HANDSHAKE ::\n");

    ServerAsym s_asym(&svConn);

    unsigned char key[100];

    s_asym.performHandshake(key);

    svConn.symCipherInit(key);

    char buffer[100];
    memset(buffer,0,100);
    int aa = svConn.decRecv((unsigned char*)buffer);
    
    printf("ricevuto %d byte, messaggio -> %.100s \n",aa,buffer);

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