#include "client/ClientConnection.cpp"
#include "client/ClientAsym.cpp"
#include "utility/Mess.h"
#include "utility/DTOs.h"
#include "utility/Hash.cpp"

ClientConnection clientConn;
ClientAsym client_asym(&clientConn);

status balance(){
    
    auto sendReq = [&](request req){
        u_int8_t req_raw = (unsigned char)req;
        int ret = clientConn.encSend(&req_raw, sizeof(request));
        return (ret > 0) ? status::OK : status::ERROR;
    };

    status outcome = sendReq(request::BALANCE);
    if(outcome == status::ERROR){
        printf("Error while sending the balance request to the server\n");
        return status::ERROR;
    }
    printf("BALANCE: request correctly sent to the server\n");

    unsigned char buffer[sizeof(int)*2 + 1];
    
    ssize_t bytes_recv = clientConn.decRecv(buffer);
    if(bytes_recv < 0){
        printf("Error occurred while recieving the balance\n");
        return status::ERROR;
    }
    
    ResponseMess* mess = (ResponseMess*) buffer;

    if(mess->sts == status::ERROR){
        printf("Error occurred while calculating the balance\n");
        return status::ERROR;
    }

    TimestampInfo t;
    memcpy(&t, mess->payload, sizeof(t));

    printf("Timestamps already consumed: %d\n", t.timestamps_remaining);
    printf("Timestamps that can still be requested: %d\n", t.timestamps_consumed);

    return status::OK;
}

unsigned char* readFromFile(char* path){

    FILE* file = fopen(path, "rb");
    if(!file){
        printf("Error occurred while operning the file\n");
        return nullptr;
    }

    fseek(file, 0, SEEK_END);
    long dim = ftell(file);

    if(dim < 0){
        printf("Invalid file dimension\n");
        fclose(file);
        return nullptr;
    }

    if(dim == 0){
        printf("File is empty\n");
        return nullptr;
    }

    fseek(file, 0, SEEK_SET);
    unsigned char* content = (unsigned char*)malloc(dim);
    if(!content){
        fclose(file);
        return nullptr;
    }

    size_t bytes_read = fread(content, 1, dim, file);
    if(bytes_read < dim){
        fclose(file);
        free(content);
        return nullptr;
    }

    fclose(file);
    return content;
}

status timestamp(){
    printf("Insert the path of the document that has to be signed: ");

    char path[MAX_PATH_LEN];
    fgets(path, MAX_PATH_LEN, stdin);
    path[strlen(path)-1] = '\0';

    unsigned char* message = readFromFile(path);
    if(!message){
        printf("Error occurred while reading from file\n");
        return status::ERROR;
    }

    unsigned char buffer[1 + HASH_SIZE];
    RequestMess* req = (RequestMess*) buffer; 
    
    req->type = request::SIGN;
    
    Hash h;
    h.calculateHash((char*)message, req->payload);

    message = nullptr;
    
    ssize_t bytes_sent = clientConn.encSend((unsigned char*) req, HASH_SIZE + 1);
    if(bytes_sent < 0){
        printf("Error occurred while sending the hash of the message\n");
        return status::ERROR;
    }

    unsigned char signature_mess[1 + HASH_SIZE + TS_SIZE + SIGNATURE_SIZE];
    ssize_t bytes_recv = clientConn.decRecv(signature_mess);

    if(bytes_recv < 0){
        printf("Error occurred while receiving the message\n");
        return status::ERROR;
    }

    if(bytes_recv == 0){
        printf("The socket was closed by the server\n");
        return status::ERROR;
    }

    SignatureMess *sig_mess = (SignatureMess*) signature_mess;
    status outcome = sig_mess->sts;

    if(outcome == status::INVALID){
        printf("All timestamps have been used\n");
        return status::ERROR;
    }
    else if(outcome == status::ERROR){
        printf("Error occurred while receiving the signature\n");
        return status::ERROR;
    }

    unsigned char mess_to_compare[HASH_SIZE + TS_SIZE];
    memcpy(mess_to_compare, req->payload, HASH_SIZE);
    memcpy(&mess_to_compare[HASH_SIZE], sig_mess->timestamp, TS_SIZE);
    
    outcome = client_asym.verifySignature(client_asym.getSignPubKey(), mess_to_compare, HASH_SIZE + TS_SIZE, sig_mess->signature);
    if(outcome == status::INVALID){
        printf("Invalid signature\n");
        return status::ERROR;
    }
    else if(outcome == status::ERROR){
        printf("Error occurred during signature verification\n");
        return status::ERROR;
    }
    
    printf("Signature created and successfully verified\n");
    return status::OK;
    
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
        command[strlen(command)-1] = '\0';
        
        status outcome;        
        if(!strcasecmp("balance", command)){
            outcome = balance();    
            if(outcome == status::ERROR){
                printf("Error while calculating the balance\n");
                break;
            }
        }
        else if(!strcasecmp("sign", command)){
            outcome = timestamp();
            if(outcome == status::ERROR){
                printf("Error in the document signature\n");
                break;
            }
        }
        else
            cout << "Invalid command inserted\n";

    }

    printf("Connection with server closed.\n");
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