#include "server/ServerConnection.cpp"

void worker(int sk){
    ServerConnection svConn(sk);
    printf("Miche funziona\n");

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

    printf("Accensione del server -> Porta: %d\n",port);
    
    jthread th_listener(th_listen, port);

    return 0;
}