#include "server/ServerConnection.cpp"
#include "server/UserInfoManager.cpp"
#include "utility/CryptoSym.cpp"

UserInfoManager uinfo;

void worker(int sk){

    string client_username("");

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

    if(!uinfo.isValid()){
        printf("Failure in loading User Info! Aborting...\n");
        return EXIT_FAILURE;
    }

    /*
    

    unsigned char key[33]={"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    unsigned char iv[17]={"bbbbbbbbbbbbbbbb"};
    
    CryptoSym c(key);

    unsigned char mess[35] = {"miche sono il bomba e sono grasso."};

    unsigned char crypto[34];

    unsigned char plain[35];

    plain[34] = '\0';

    unsigned char aad[4] = {"bem"};

    unsigned char tag[16];

    int cipherlen;
    int plen;

    c.encrypt(mess,34,iv,aad,3, tag,crypto,&cipherlen);

    printf("Cipherlen: %d\n",cipherlen);

    status culo = c.decrypt(crypto,cipherlen,iv,aad,3,tag,plain,&plen);

    if(culo == status::ERROR){
        printf("MERDA\n");
        return -1;
    }

    printf("plen: %d, plain: %s\n", plen, (char*)plain);
    */

    printf("Server is turning on -> Port: %d\n",port);
    
    jthread th_listener(th_listen, port);

    return EXIT_SUCCESS;
}