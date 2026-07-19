#ifndef CONSTANTS
#define CONSTANTS

#include "all.h"

// addresses
#define DEFAULT_PORT 8080
#define SERVER_ADDRESS "127.0.0.1"

// User json path
#define USER_CREDENTIALS_PATH "server/UserInfo/UserCredentials.json"


using namespace std;
using json = nlohmann::json;

enum class status{
    OK,
    ERROR
};

#endif