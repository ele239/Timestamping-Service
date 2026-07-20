#include "client/ClientConnection.cpp"
#include "client/ClientAsym.cpp"


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

    ClientAsym client_asym(&clientConn);
    
    unsigned char shared_secret[SHARED_SECRET_SIZE];
    client_asym.performHandshake(shared_secret);

    unsigned char message[23] = {"Mi sono rotta il cazzo"};

    clientConn.symCipherInit(shared_secret);
    clientConn.encSend(message, 23);



        
    return EXIT_SUCCESS;
}