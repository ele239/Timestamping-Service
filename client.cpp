#include "client/SessionManager.cpp"
#include "utility/Mess.h"

SessionManager session;

void th_kbd(){

    #ifdef COMPLETE_INFO
    printf(CYAN("CLIENT_THREAD") "Worker thread started. Attempting login...\n");
    #endif

    if(session.login() != status::OK){
        printf(WARNING_MESS "Authentication failed. Closing connection.\n");
        return;
    }

    while(true){
        
        printf("\n-------------------------- COMMAND INTERFACE --------------------------\n");
        printf(INDIGO("Insert a valid command")"\n");
        printf("- " YELLOW("Balance") "shows the number of available and consumed timestamps\n");
        printf("- " YELLOW("Sign") "request to sign a document\n");
        printf("- " YELLOW("Verify") "verify a document signature\n");
        printf("- " YELLOW("Exit") "quit the application\n");

        printf(INDIGO("Insert command"));
        char command[MAX_COMMAND_LEN];
        fgets(command, MAX_COMMAND_LEN, stdin);
        command[strlen(command)-1] = '\0';

        #ifdef COMPLETE_INFO
        printf( INDIGO("COMMAND") "Received command '%s' from user\n", command);
        #endif
        
        status outcome;        
        if(!strcasecmp("balance", command)){
            outcome = session.balance();    
            if(outcome == status::ERROR){
                printf(ERROR_MESS "Error while calculating the balance\n");
                break;
            }
        }
        else if(!strcasecmp("sign", command)){
            outcome = session.timestamp();
            if(outcome == status::ERROR){
                printf(ERROR_MESS "\nError in the document signature\n");
                break;
            }
        }
        else if(!strcasecmp("verify", command)){
            outcome = session.verify();
            if(outcome == status::ERROR){
                printf(ERROR_MESS "Error in signature verification\n");
                break;
            }
        }
        else if(!strcasecmp("exit", command)){
            printf(SKYBLUE("STATUS") "Exiting ...\n");
            break;
        }
        else
            printf(INDIGO("COMMAND") "Invalid command inserted\n");
            
        this_thread::sleep_for(2s); 
    }

    printf(SKYBLUE("STATUS") "Connection with server closed\n");
}


int main(int argc, char* argv[]){

    while(true){
        
        printf("\n-------------------------- COMMAND INTERFACE --------------------------\n");
        printf(INDIGO("Insert a valid command")"\n");
        printf("- " YELLOW("Login") "connect to the Time-Stamping server\n");
        printf("- " YELLOW("Verify") "verify a document signature\n");
        printf("- " YELLOW("Exit") "quit the application\n");

        printf(INDIGO("Insert command"));
        char command[MAX_COMMAND_LEN];
        fgets(command, MAX_COMMAND_LEN, stdin);
        command[strlen(command)-1] = '\0';

        #ifdef COMPLETE_INFO
        printf( INDIGO("COMMAND") "Received command '%s' from user\n", command);
        #endif
        
        status outcome;
        if(!strcasecmp("login", command)){
            break;
        }
        else if(!strcasecmp("exit", command)){
            printf(SKYBLUE("STATUS") "Exiting ...\n");
            break;
        }
        else if(!strcasecmp("verify", command)){
            outcome = session.verify();
            if(outcome == status::ERROR){
                printf(ERROR_MESS "Error in signature verification, quitting.\n");
                return EXIT_FAILURE;
            }
        }else
            printf(INDIGO("COMMAND") "Invalid command inserted\n");
            
        this_thread::sleep_for(2s); 
    }

    int port = (argc == 1) ? DEFAULT_PORT : atoi(argv[1]);
    #ifdef COMPLETE_INFO
    printf(GREEN("MAIN") "Using port %d\n", port);
    #endif

    status creation = session.createSocket();

    if(creation == status::ERROR){
        printf(ERROR_MESS "Error while creating the socket\n");
        return EXIT_FAILURE;
    }

    #ifdef COMPLETE_INFO
    printf(GREEN("MAIN") "Socket created successfully\n");
    #endif
    
    printf(GREEN("MAIN") "Connecting to server...\n");
    
    status connection = session.connectTo(SERVER_ADDRESS, port);
    if(connection ==  status::ERROR){
        printf(ERROR_MESS "Connection failed \n");
        return EXIT_FAILURE;
    }
    
    #ifdef COMPLETE_INFO
    printf(GREEN("MAIN") "Connection established. Attemping Handshake\n");
    #endif
    
    status outcome = session.performHandshake();

    if(outcome != status::OK){
        printf(ERROR_MESS "Failure during the handshake protocol. Aborting the connection...\n");
        return EXIT_FAILURE;
    
    }
    
    #ifdef COMPLETE_INFO
    printf(GREEN("MAIN") "Handshake Performed successfully!\n");
    #endif

    #ifdef COMPLETE_INFO
    printf(GREEN("MAIN") "Starting worker thread\n");
    #endif

    jthread keyboard(th_kbd);
    return EXIT_SUCCESS;
}