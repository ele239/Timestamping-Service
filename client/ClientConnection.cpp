#ifndef CLIENT_CONN
#define CLIENT_CONN

#include "../utility/Connection.cpp"
#include "../utility/CryptoSym.cpp"

class ClientConnection : public Connection{

    public:
    status connectTo(const char* server_addr, short port){
        
        memset((void*)&socket_info, 0 ,sizeof(sockaddr));

        socket_info.sin_family = AF_INET;
        socket_info.sin_port = htons(port);

        inet_pton(AF_INET, server_addr, &socket_info.sin_addr);
        
        #ifdef COMPLETE_INFO
        printf("CONNECT: Attempting connection to %s:%d\n", server_addr, port);
        #endif

        while(true){    
            int res = connect(sk, (struct sockaddr *)&socket_info, sizeof(sockaddr));

            if(res < 0){
                if(errno == ECONNREFUSED || errno == ETIMEDOUT || errno == ENETUNREACH){

                    #ifdef COMPLETE_INFO
                    printf("CONNECT: Connection attempt failed, retrying in 1s...\n");
                    #endif

                    printf("Waiting for a response...\n");
                    this_thread::sleep_for(1s);
                    continue;
                }

                #ifdef COMPLETE_INFO
                printf("CONNECT: Unrecoverable error, aborting connection attempt\n");
                #endif
                return status::ERROR;
            }
            else{
                #ifdef COMPLETE_INFO
                printf("CONNECT: Successfully connected to %s:%d\n", server_addr, port);
                #endif
                return status::OK;
            }
        }
    }

    status createClientSocket(){

        #ifdef COMPLETE_INFO
        printf("SOCKET: Creating client socket...\n");
        #endif
        return this->createSocket();
    }
};

#endif