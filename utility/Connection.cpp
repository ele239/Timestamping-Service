#include "../include/const.h"

class Connection{

protected:
    int sk;
    sockaddr_in socket_info;

    status createSocket(){
        sk = socket(AF_INET, SOCK_STREAM, 0);
        if(sk < 0){
            return status::ERROR;
        }else
            return status::OK;
    }

    ~Connection(){
        close(sk);
    }

public:

    status sendMess(const char *buf, size_t len){

        ssize_t bytes_sent =  send(sk, buf, len, MSG_NOSIGNAL);
        if(bytes_sent <= len)
            return status::ERROR;
        else
            return status::OK;
    }

    status recvMess(const char *buf, size_t len){

        ssize_t bytes_recv =  recv(sk, (void*)buf, len, 0);
        
        if(bytes_recv <= len)
            return status::ERROR;
        else
            return status::OK;
    }


};