#ifndef MESS
#define MESS
#include "../include/const.h"

struct RequestMess{
    request type;
    unsigned char payload[];
};

struct ResponseMess{
    status type;
    unsigned char payload[];
};
#endif