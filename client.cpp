#include "client/ClientConnection.cpp"
#include "client/ClientAsym.cpp"
#include "utility/Mess.h"
#include "utility/DTOs.h"

ClientConnection clientConn;
ClientAsym client_asym(&clientConn);

void balance(){
    
    auto sendReq = [&](request req){
        u_int8_t req_raw = (unsigned char)req;
        int ret = clientConn.encSend(&req_raw, sizeof(request));
        return (ret > 0) ? status::OK : status::ERROR;
    };

    status outcome = sendReq(request::BALANCE);
    if(outcome == status::ERROR){
        printf("Error while sending the balance request to the server\n");
        return;
    }
    printf("BALANCE: request correctly sent to the server\n");

    unsigned char buffer[sizeof(int)*2 + 1];
    
    ssize_t bytes_recv = clientConn.decRecv(buffer);
    if(bytes_recv < 0){
        printf("Error occurred while recieving the balance\n");
    }
    
    ResponseMess* mess = (ResponseMess*) buffer;
    status req_status = mess->type;
    if(req_status == status::ERROR){
        printf("Error occurred while calculating the balance\n");
        return;
    }

    TimestampInfo t;
    memcpy(&t, mess->payload, sizeof(t));

    printf("Timestamps already consumed: %d\n", t.timestamps_remaining);
    printf("Timestamps that can still be request: %d\n", t.timestamps_consumed);

}


void timestamp(){
    printf("Insert the path of the document that has to be signed: ");

    char path[MAX_PATH_LEN];
    fgets(path, MAX_PATH_LEN, stdin);
    path[strlen(path)] = '\0';


    //readFromFile()
}

void th_kbd(){
    string line; 

    auto recvOutcome = [&](){
        unsigned char outcome_raw;
        int ret = clientConn.decRecv(&outcome_raw);
        status outcome = (status)outcome_raw;
        return (ret > 0) ? outcome : status::ERROR;
    };

    while(true){

        char username[MAX_USERNAME_LEN];
        char pwd[MAX_PWD_LEN];
        
        printf("------------- LOGIN -------------\n");
        printf("Username: \n");
        fgets(username, sizeof(username), stdin);
        printf("Password: \n");
        fgets(pwd, sizeof(pwd), stdin);

        size_t username_len = strlen(username);
        size_t pwd_len = strlen(pwd);
        unsigned char credentials_len = username_len + pwd_len;
        username[username_len - 1] = '\0';
        pwd[pwd_len - 1] = '\0';
 
        unsigned char credentials[credentials_len];
        memcpy(credentials, username, username_len);
        memcpy(&credentials[username_len], pwd, pwd_len);
        
        int bytes_sent = clientConn.encSend(credentials, credentials_len);

        if(bytes_sent < 0){
            printf("Error while sending the credentials to the server\n");
            continue;
        }
        printf("E che bravo! Hai mandato il messaggio\n");

        status outcome = recvOutcome();
        if(outcome == status::INVALID){
            printf("Invalid credentials\n");
            continue;
        }
        else if(outcome == status::ERROR){
            printf("Hai cagato fuori dal vaso troppe volte\n");
            return;
        }
        else{
            printf("Authentication succeeded\n");
            break;
        }
    }

    while(true){
        
        printf("Insert a valid command: \n - Balance: to see the number of available and consumed timestamps\n - Sign: merda\n");
        
        char command[MAX_COMMAND_LEN];
        fgets(command, MAX_COMMAND_LEN, stdin);
        command[strlen(command)] = '\0';
        
        if(strcasecmp("balance", command))
            balance();    
        else if(strcasecmp("sign", command))
            timestamp();
        else
            cout << "Invalid command inserted\n";

    }
}


int main(int argc, char* argv[]){

    int port = (argc == 1) ? DEFAULT_PORT : atoi(argv[1]);

    status creation = clientConn.createClientSocket();

    if(creation == status::ERROR){
        printf("Error while establishing the connection \n");
        return EXIT_FAILURE;
    }
    
    printf("Connecting to server...\n");
    
    status connection = clientConn.connectTo(SERVER_ADDRESS, port);
    if(connection ==  status::ERROR){
        printf("Connection failed \n");
        return EXIT_FAILURE;
    }

    printf("Connection established. Attemping Handshake\n");
    
    status outcome = client_asym.performHandshake();

    if(outcome != status::OK){
        printf("The handshake did not go well. Aborting the connection...\n");
        return EXIT_FAILURE;
    
    }
    printf("Handshake Performed successfully!\n");

    jthread keyboard_warrior(th_kbd);
        
    return EXIT_SUCCESS;
}