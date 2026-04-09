/* =============================================================================
 * server.c — Server entrypoint and lifecycle
 * =============================================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "core/server_state.h"
#include "core/chat_logic.h"
#include "db/user_db.h"

client_state_t clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int running = 1;

static int server_fd = -1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
    if (server_fd >= 0) close(server_fd);
}

int main(int argc, char *argv[])
{
    int port = SERVER_PORT;
    struct sockaddr_in addr;
    crypto_ctx_t init_ctx;
    int loaded_users = 0;

    if (argc >= 2) port = atoi(argv[1]);

    if (crypto_open(&init_ctx) < 0) {
        fprintf(stderr, "[server] Cannot open %s - is the driver loaded?\n",
                CRYPTO_CHAT_DEV_PATH);
        return 1;
    }

    if (user_db_init(USER_DB_PATH) < 0) {
        fprintf(stderr, "[server] Cannot initialize SQLite user DB at %s\n",
                USER_DB_PATH);
        crypto_close(&init_ctx);
        return 1;
    }

    user_db_add_plain(&init_ctx, "alice", "password123");
    user_db_add_plain(&init_ctx, "bob", "secret456");
    user_db_add_plain(&init_ctx, "charlie", "hello789");
    user_db_add_plain(&init_ctx, "admin", "admin@CryptoChat#2024");
    if (user_db_count_users(&loaded_users) == 0) {
        printf("[server] %d users loaded from SQLite (%s)\n",
               loaded_users, USER_DB_PATH);
    }
    crypto_close(&init_ctx);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        user_db_close();
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        user_db_close();
        return 1;
    }
    if (listen(server_fd, BACKLOG) < 0) {
        perror("listen");
        close(server_fd);
        user_db_close();
        return 1;
    }

    printf("[server] CryptoChat server listening on port %d\n", port);
    printf("[server] Encryption: AES-256-CBC | Hash: SHA-256 (kernel driver)\n");
    printf("[server] Press Ctrl-C to stop\n\n");

    while (running) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int cli_fd = accept(server_fd,
                            (struct sockaddr *)&cli_addr, &cli_len);
        if (cli_fd < 0) {
            if (running) perror("accept");
            break;
        }

        pthread_mutex_lock(&clients_mutex);
        int slot = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i].active) {
                slot = i;
                break;
            }
        }

        if (slot < 0) {
            pthread_mutex_unlock(&clients_mutex);
            fprintf(stderr, "[server] Max clients reached\n");
            close(cli_fd);
            continue;
        }

        memset(&clients[slot], 0, sizeof(clients[slot]));
        clients[slot].sock = cli_fd;
        clients[slot].active = 1;
        clients[slot].addr = cli_addr;
        clients[slot].crypto.fd = -1;
        pthread_mutex_init(&clients[slot].send_mutex, NULL);
        pthread_mutex_unlock(&clients_mutex);

        printf("[server] New connection from %s:%d (slot %d)\n",
               inet_ntoa(cli_addr.sin_addr),
               ntohs(cli_addr.sin_port), slot);

        pthread_create(&clients[slot].thread, NULL,
                       client_thread, &clients[slot]);
        pthread_detach(clients[slot].thread);
    }

    printf("\n[server] Shutting down...\n");
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) close(clients[i].sock);
    }
    pthread_mutex_unlock(&clients_mutex);

    user_db_close();
    return 0;
}
