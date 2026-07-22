#ifndef SERVER_CONN
#define SERVER_CONN

#include "../utility/Connection.cpp"
#include "../utility/CryptoSym.cpp"


class ServerConnection : public Connection{

public: 

    ServerConnection(){}
    
    ServerConnection(int socket){
        sk=socket;
    }

    status bindSocket(short port){
        
        memset((void*)&socket_info, 0 ,sizeof(sockaddr));

        socket_info.sin_family = AF_INET;
        socket_info.sin_port = htons(port);
        socket_info.sin_addr.s_addr = INADDR_ANY;

        int res = bind(sk,(const sockaddr *) &socket_info ,sizeof(sockaddr));

        if(res == -1)
            return status::ERROR;
        else
            return status::OK;
    }

    status createListenSocket(short port){
        status outcome = this->createSocket();
        
        if(outcome == status::ERROR)
            return outcome;

        outcome = bindSocket(port);

        if(outcome == status::ERROR)
            return outcome;

        int res = listen(sk, 10);

        if(res < 0)
            return status::ERROR;
        else
            return status::OK;
    }

    int acceptConnection(){
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        return accept(sk, (struct sockaddr *)&client_addr, &client_len);
        
    }
};

#endif