#include "../include/const.h"

class Connection{

protected:
    int sk;
    sockaddr_in socket_info;

    CryptoSym * my_cipher = nullptr;
    CryptoSym * other_cipher = nullptr; // da considerare?

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

    ssize_t sendMess(const char *buf, size_t len){
        return send(sk, buf, len, MSG_NOSIGNAL);
    }

    ssize_t recvMess(const char *buf, size_t len){
        return recv(sk, (void*)buf, len, 0);
    }

    ssize_t encSend(){

    }

    ssize_t decRecv(){
        
    }


};