#include "server/UserInfoManager.cpp"
#include "server/ResponseManager.cpp"

UserInfoManager uinfo;
ServerAsym Server_Asymmetric_Keys;


void worker(int sk){

    ResponseManager rm(sk, Server_Asymmetric_Keys, &uinfo);

    status outcome;

    printf(":: NEW CONNECTION REQUEST ::\n");

    outcome = rm.performHandshake();

    if(outcome != status::OK){
        printf("The handshake did not go well. Aborting the connection...\n");
        return;
    }

    printf("Handshake Performed successfully!\n");

    printf("Awaiting for User Authentication\n");

    unsigned char tries = MAX_TRIES;

    while(tries){
        printf("Tries remaining: %d\n", tries);

        outcome = rm.authenticationAttempt();

        if(outcome == status::ERROR)
            return;

        if(outcome == status::OK)
            break;

        tries--;
        if(tries > 0)
            rm.sendStatus(outcome);
    }
    if(!tries){
        printf("The user failed to authenticate. Aborting the connection...\n");
        rm.sendStatus(status::ERROR);
        return;
    }else{
        printf("The user \"%s\" has logged in successfully.\n",rm.getUsername().c_str());
        rm.sendStatus(status::OK);
    }

    while(true){
        
        outcome = rm.manageRequests();

        if(outcome != status::OK)
            break;
    }

    printf("Connection Terminated with \"%s\". Thread exiting...\n", rm.getUsername().c_str());

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