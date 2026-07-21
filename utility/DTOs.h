#ifndef DTOS
#define DTOS

#include "../include/const.h"

struct TimestampInfo{
    unsigned int timestamps_remaining;
    unsigned int timestamps_consumed;
};

struct UserInfo{
    string username;
    string salt;
    string password;

    unsigned int timestamps_remaining;
    unsigned int timestamps_consumed;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(UserInfo, username, salt, password, timestamps_remaining, timestamps_consumed)
#endif