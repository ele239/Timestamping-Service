#include "client/ClientConnection.cpp"

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
        
    return EXIT_SUCCESS;
}