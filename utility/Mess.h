#ifndef MESS
#define MESS
#include "../include/const.h"

// ASYMMETRIC HANDSHAKE MESSAGES

struct ClientHello{
    unsigned char nonce[NONCE_SIZE];
    unsigned char eph_key_raw[EPH_KEY_SIZE];
};

struct ServerHello : ClientHello{
    unsigned char signature[SIGNATURE_SIZE];
};

struct Conversation{
    unsigned char c_nonce[NONCE_SIZE];
    unsigned char s_nonce[NONCE_SIZE];
    unsigned char c_eph_key_raw[EPH_KEY_SIZE]; 
    unsigned char s_eph_key_raw[EPH_KEY_SIZE]; 
};

// SYMMETRIC MESSAGES
struct RequestMess{
    request type;
    unsigned char payload[];
};

struct ResponseMess{
    status sts;
    unsigned char payload[];
};

struct SignatureMess{
    status sts;
    unsigned char hash[HASH_SIZE];
    unsigned char timestamp[TS_SIZE];
    unsigned char signature[SIGNATURE_SIZE];
};

#endif