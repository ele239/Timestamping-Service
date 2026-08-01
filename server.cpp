#include "server/UserInfoManager.cpp"
#include "server/ResponseManager.cpp"

UserInfoManager uinfo;
ServerAsym Server_Asymmetric_Keys;

vector<jthread> workers; 

mutex mtx;
queue<int> sockets;
condition_variable sockets_cv;

int getAvailableSocket(){

    int socket = -1;

    unique_lock<mutex> lk(mtx);

    sockets_cv.wait(lk, [=](){return !sockets.empty();});

    socket = sockets.front();
    sockets.pop();

    return socket;
}

void worker(){

    int sk =-1;
    while(true){
        
        sk = getAvailableSocket();

        ResponseManager rm(sk, Server_Asymmetric_Keys, &uinfo);

        status outcome;

        printf("\n" SKYBLUE("SERVER_THREAD") "Worker thread started\n");

        printf(SKYBLUE("SERVER_THREAD") "Performing Handshake...\n");


        outcome = rm.performHandshake();

        if(outcome != status::OK){
            printf(WARNING_MESS "The handshake did not go well. Aborting the connection...\n");
            continue;
        }

        printf(SKYBLUE("SERVER_THREAD") "Handshake Performed successfully!\n");

        printf(SKYBLUE("SERVER_THREAD") "Awaiting for User Authentication\n");

        unsigned char tries = MAX_TRIES;

        while(tries){
            printf(SKYBLUE("SERVER_THREAD") "Tries remaining: %d\n", tries);

            outcome = rm.authenticationAttempt();

            if(outcome == status::ERROR){
                printf(ERROR_MESS "An error occurred during authentication. Aborting...\n");
                rm.sendStatus(status::ERROR);
                break;
            }

            if(outcome == status::OK)
                break;

            tries--;
            if(tries > 0)
                rm.sendStatus(outcome);
        }
        if(!tries || outcome != status::OK){
            printf(WARNING_MESS "The user failed to authenticate. Aborting the connection...\n");
            rm.sendStatus(status::ERROR);
            continue;
        }else{
            printf(SKYBLUE("SERVER_THREAD") "The user \"%s\" has logged in successfully.\n",rm.getUsername().c_str());
            rm.sendStatus(status::OK);
        }

        while(true){
            
            outcome = rm.manageRequests();

            if(outcome == status::ERROR)
                break;
        }

        printf("\n" SKYBLUE("SERVER_THREAD") "Connection Terminated with \"%s\". Thread exiting...\n", rm.getUsername().c_str());
    }
}

void th_listen(short port){

    ServerConnection svConn;

    status outcome;

    int client_sock;

    printf(PURPLE("LISTEN_THREAD") "Creating Listen Socket...\n");

    outcome = svConn.createListenSocket(port);

    
    if(outcome == status::ERROR){
        printf(ERROR_MESS "FATAL ERROR WHEN CREATING SOCKET!! QUITTING.\n");
        return;
    }

    printf(PURPLE("LISTEN_THREAD") "Listen Socket Created. Waiting for Connections...\n");

    

    while(true){
        client_sock = svConn.acceptConnection();
        if(client_sock < 0){
            printf(ERROR_MESS "Unexpected outcome during accept...\n");
            continue;
        }
        printf(PURPLE("LISTEN_THREAD") "Connection received! Starting new Worker...\n");

        unique_lock<mutex> lk(mtx);
        sockets.push(client_sock);

        lk.unlock();
        sockets_cv.notify_one();
    
    }

}


int main(int argc, char* argv[]){

    in_port_t port = (argc == 1) ? DEFAULT_PORT : atoi(argv[1]);

    if(!uinfo.isValid()){
        printf(ERROR_MESS "Failure in loading User Info! Aborting...\n");
        return EXIT_FAILURE;
    }

    printf(GREEN("MAIN") "Server is turning on -> Port: %d\n",port);

    printf(GREEN("MAIN") "Creating thread pool -> Size: %d Threads\n",NUM_THREADS);

    for(int i = 0; i < NUM_THREADS; i++)
        workers.emplace_back(worker);
        

    printf(GREEN("MAIN") "Starting Listen Thread...\n\n");
    
    thread th_listener(th_listen, port);

    th_listener.join();

    return EXIT_SUCCESS;
}