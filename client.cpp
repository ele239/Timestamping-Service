#include "client/ClientConnection.cpp"
#include "client/ClientAsym.cpp"


void th_kbd(){
    string line; 

    while(true){

        char username[MAX_USERNAME_LEN];
        char pwd[MAX_PWD_LEN];
        
        printf("------------- LOGIN -------------\n");
        printf("Username: \n");
        fgets(username, sizeof(username), stdin);
        printf("Password: \n");
        fgets(pwd, sizeof(pwd), stdin);

        /*unsigned char username_len = ;
        unsigned char pwd_len = pwd.length();
        unsigned char credentials_len = username_len + pwd_len;
        unsigned char credentials[credentials_len];*/
        
    
    }

    while(true){
        cout << "Insert a valid command: \n";
        
        if(!getline(cin, line)){
            printf("Error while reading the command\n");
            continue; 
        }

        /*if(line == "balance")
           // balance();
        else if(line == "authentication")
           // login();
        else if(line == "request operation")
           // timestamp();
        else 
            cout << "Invalid command inserted\n";*/
    }
}


int main(int argc, char* argv[]){

    int port = (argc == 1) ? DEFAULT_PORT : atoi(argv[1]);


    ClientConnection clientConn;
    status creation = clientConn.createClientSocket();

    if(creation == status::ERROR){
        printf("Error while establishing the connection \n");
        return EXIT_FAILURE;
    }

    status connection = clientConn.connectTo(SERVER_ADDRESS, port);
    if(connection ==  status::ERROR){
        printf("Connection failed \n");
        return EXIT_FAILURE;
    }


    jthread keyboard_warrior(th_kbd);
        
    return EXIT_SUCCESS;
}