#ifndef CONSTANTS
#define CONSTANTS

#include "all.h"

// Addresses
#define DEFAULT_PORT 8080
#define SERVER_ADDRESS "127.0.0.1"

// User json path
#define USER_CREDENTIALS_PATH "server/UserInfo/UserCredentials.json"

// Signature path
#define SIGNATURE_FILE_PATH "client/Signatures.txt"

// Server Keys path
#define SERVER_SIGN_PRIV "server/keys/server_sign_priv.pem"
#define SERVER_SIGN_PUB "server/keys/server_sign_pub.pem"

#define SERVER_HANDSHAKE_PUB "server/keys/server_handshake_pub.pem"
#define SERVER_HANDSHAKE_PRIV "server/keys/server_handshake_priv.pem"

// Message size
#define MAX_PLAINTEXT_SIZE 105
#define IV_SIZE 16
#define TAG_SIZE 16
#define MAX_CIPHERTEXT_SIZE (MAX_PLAINTEXT_SIZE + IV_SIZE + TAG_SIZE)
#define MAX_USERNAME_LEN 30
#define MAX_PWD_LEN 30

// Key sizes
#define EPH_KEY_SIZE 32
#define SHARED_SECRET_SIZE 32
#define AES_KEY_SIZE 32

// Signature size
#define SIGNATURE_SIZE 64

// Nonce size
#define NONCE_SIZE 32

// Hash size
#define HASH_SIZE 32

// Max number of authentication tries
#define MAX_TRIES 3

// Max command length 
#define MAX_COMMAND_LEN 9

// Max path length
#define MAX_PATH_LEN 150

// Max timestamp size
#define TS_SIZE 8

#define COMPLETE_INFO

#define COLOR_GREEN   "\033[32m"
#define COLOR_RED     "\033[31m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_RESET    "\033[0m"

using namespace std;
using json = nlohmann::json;

enum class status : uint8_t{
    OK,
    ERROR,
    INVALID
};

enum class request : uint8_t{
    BALANCE,
    SIGN,
    EXIT
};

#endif