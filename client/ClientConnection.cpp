#include "../utility/Connection.cpp"

class ClientConnection : public Connection{

    public:
    status connectTo(const char* server_addr, short port){
        
        memset((void*)&socket_info, 0 ,sizeof(sockaddr));

        socket_info.sin_family = AF_INET;
        socket_info.sin_port = htons(port);

        inet_pton(AF_INET, server_addr, &socket_info.sin_addr);

        while(true){    
            int res = connect(sk, (struct sockaddr *)&socket_info, sizeof(sockaddr));

            if(res < 0){
                if(errno == ECONNREFUSED || errno == ETIMEDOUT || errno == ENETUNREACH){
                    printf("Waiting for a response...\n");
                    this_thread::sleep_for(1s);
                    continue;
                }
                return status::ERROR;
            }
            else
                return status::OK;
        }
    }

    status createClientSocket(){
        return this->createSocket();
    }
};