#include <sys/socket.h> // Funzioni core (socket, bind, listen, accept)
#include <netinet/in.h> // Famiglie di indirizzi e strutture (sockaddr_in)
#include <arpa/inet.h>  // Conversioni IP (inet_pton, htons)
#include <unistd.h>     // Chiusura descrittori (close)
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <cstring>
#include <thread>
#include <chrono>
#include <stdlib.h>
#include <mutex>
#include <vector>
