#include "client/SessionManager.cpp"
#include "utility/Mess.h"

SessionManager session;

void th_kbd(){

    if(session.login() != status::OK){
        #ifdef COMPLETE_INFO
        printf("LOGIN: ");
        #endif
        printf("Authentication failed. Closing connection.\n");
        return;
    }

    while(true){
        
        printf("\n-------------------------- COMMAND INTERFACE --------------------------\n");
        printf("Insert a valid command: \n");
        printf("- Balance: shows the number of available and consumed timestamps\n");
        printf("- Sign: request to sign a document\n");
        printf("- Verify: verify a document signature\n");
        printf("- Exit\n");

        printf("Insert command: ");
        char command[MAX_COMMAND_LEN];
        fgets(command, MAX_COMMAND_LEN, stdin);
        command[strlen(command)-1] = '\0';

        #ifdef COMPLETE_INFO
        printf("COMMAND: Received command '%s' from user\n", command);
        #endif
        
        status outcome;        
        if(!strcasecmp("balance", command)){
            outcome = session.balance();    
            if(outcome == status::ERROR){
                printf("ERROR: Error while calculating the balance\n");
                break;
            }
        }
        else if(!strcasecmp("sign", command)){
            outcome = session.timestamp();
            if(outcome == status::ERROR){
                printf("ERROR: Error in the document signature\n");
                break;
            }
        }
        else if(!strcasecmp("verify", command)){
            outcome = session.verify();
            if(outcome == status::ERROR){
                printf("ERROR: Error in signature verification\n");
                break;
            }
        }
        else if(!strcasecmp("exit", command)){
            printf("Exiting ...\n");
            return;
        }
        else{
            #ifdef COMPLETE_INFO
            printf("COMMAND: ");
            #endif
            printf("Invalid command inserted\n");
        }
            
        this_thread::sleep_for(3s); 
    }

    printf("Connection with server closed\n");
}


int main(int argc, char* argv[]){

    int port = (argc == 1) ? DEFAULT_PORT : atoi(argv[1]);
    #ifdef COMPLETE_INFO
    printf("MAIN: Using port %d\n", port);
    #endif

    status creation = session.createSocket();

    if(creation == status::ERROR){
        printf("ERROR: Error while creating the socket\n");
        return EXIT_FAILURE;
    }

    #ifdef COMPLETE_INFO
    printf("MAIN: Socket created successfully\n");
    #endif
    
    #ifdef COMPLETE_INFO
    printf("MAIN: ");
    #endif
    printf("Connecting to server...\n");
    
    status connection = session.connectTo(SERVER_ADDRESS, port);
    if(connection ==  status::ERROR){
        printf("ERROR: Connection failed \n");
        return EXIT_FAILURE;
    }
    
    #ifdef COMPLETE_INFO
    printf("\nMAIN: Connection established. Attemping Handshake\n");
    #endif
    
    status outcome = session.performHandshake();

    if(outcome != status::OK){
        printf("ERROR: Failure during the handshake protocol. Aborting the connection...\n");
        return EXIT_FAILURE;
    
    }
    
    #ifdef COMPLETE_INFO
    printf("MAIN: Handshake Performed successfully!\n");
    #endif

    #ifdef COMPLETE_INFO
    printf("MAIN: Starting keyboard input thread\n");
    #endif
    jthread keyboard(th_kbd);
    return EXIT_SUCCESS;
}