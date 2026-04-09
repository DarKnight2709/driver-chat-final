#ifndef SERVER_STATE_H
#define SERVER_STATE_H

#include <stdint.h>
#include <pthread.h>
#include <netinet/in.h>

#include "../../crypto_lib.h"

#define SERVER_PORT 9090
#define MAX_CLIENTS 32
#define BACKLOG 16
#define USER_DB_PATH "./server/users.db"
#define SERVER_SECRET "CryptoChatServerSecret_v1_DO_NOT_SHARE"

typedef struct {
    int sock;
    int active;
    char username[MAX_USERNAME_LEN];
    uint8_t session_key[AES_KEY_SIZE];
    uint8_t session_salt[16];
    struct sockaddr_in addr;
    pthread_t thread;
    crypto_ctx_t crypto;
    pthread_mutex_t send_mutex;
} client_state_t;

extern client_state_t clients[MAX_CLIENTS];
extern pthread_mutex_t clients_mutex;
extern volatile int running;

#endif
