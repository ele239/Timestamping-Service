#ifndef CONSTANTS
#define CONSTANTS

#include "all.h"

// Addresses
#define DEFAULT_PORT 8080
#define SERVER_ADDRESS "127.0.0.1"

// User json path
#define USER_CREDENTIALS_PATH "server/UserInfo/UserCredentials.json"

// Server Keys path
#define SERVER_SIGN_PRIV "server/keys/server_sign_priv.pem"
#define SERVER_SIGN_PUB "server/keys/server_sign_pub.pem"

#define SERVER_HANDSHAKE_PUB "server/keys/server_handshake_pub.pem"
#define SERVER_HANDSHAKE_PRIV "server/keys/server_handshake_priv.pem"

// Message size
#define MAX_PLAINTEXT_SIZE 100
#define IV_SIZE 16
#define TAG_SIZE 16
#define MAX_CIPHERTEXT_SIZE (MAX_PLAINTEXT_SIZE + IV_SIZE + TAG_SIZE)
#define MAX_USERNAME_LEN 30
#define MAX_PWD_LEN 30

// Key sizes
#define EPH_KEY_SIZE 32
#define SHARED_SECRET_SIZE 32
#define AES_KEY_SIZE 32

// signature size
#define SIGNATURE_SIZE 64

// nonce size
#define NONCE_SIZE 32

#define HASH_SIZE 32

#define MAX_TRIES 3;

using namespace std;
using json = nlohmann::json;

enum class status{
    OK,
    ERROR,
    INVALID
};

#endif