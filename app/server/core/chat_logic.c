#include "chat_logic.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "server_state.h"
#include "../protocol/frame.h"
#include "../db/user_db.h"

static int authenticate_with_frame(client_state_t *c,
                                   const struct chat_frame *fixed_f);
static void broadcast_msg(client_state_t *sender,
                          const char *msg, size_t msg_len);
static void list_users(client_state_t *c);
static void list_users_unlocked(client_state_t *c);
static void handle_password_change(client_state_t *c,
                                   const struct chat_frame *f);

static void announce_join(client_state_t *c)
{
    int already_online = 0;
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && &clients[i] != c && strcmp(clients[i].username, c->username) == 0) {
            already_online = 1;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    if (!already_online) {
        char bcast_buf[MAX_USERNAME_LEN + MAX_MSG_LEN + 64];
        snprintf(bcast_buf, sizeof(bcast_buf),
                 "*** %s joined the chat ***", c->username);
        broadcast_msg(c, bcast_buf, strlen(bcast_buf));
    }
}

static int handle_pre_auth_frame(client_state_t *c, const struct chat_frame *f,
                                 int *auth_done)
{
    if (f->type == MSG_TYPE_REGISTER) {
        struct auth_payload rp;
        uint32_t plen = 0;
        uint8_t zero_key[AES_KEY_SIZE] = {0};
        int reg_rc;

        if (crypto_aes_decrypt(&c->crypto, zero_key, f->iv,
                               f->payload, f->payload_len,
                               (uint8_t *)&rp, &plen) < 0) {
            send_frame_with_key(c, MSG_TYPE_REG_FAIL,
                                "Decrypt error", 13, zero_key);
            return 0;
        }

        if (plen < sizeof(struct auth_payload)) {
            send_frame_with_key(c, MSG_TYPE_REG_FAIL,
                                "Invalid payload", 15, zero_key);
            return 0;
        }

        rp.username[MAX_USERNAME_LEN - 1] = '\0';
        if (rp.username[0] == '\0') {
            send_frame_with_key(c, MSG_TYPE_REG_FAIL,
                                "Username required", 17, zero_key);
            return 0;
        }

        reg_rc = user_db_add(rp.username, rp.password_hash);
        if (reg_rc == 1) {
            send_frame_with_key(c, MSG_TYPE_REG_FAIL,
                                "User already exists", 19, zero_key);
            return 0;
        }
        if (reg_rc < 0) {
            send_frame_with_key(c, MSG_TYPE_REG_FAIL,
                                "Database error", 14, zero_key);
            return 0;
        }

        printf("[server] New user registered: %s\n", rp.username);
        send_frame_with_key(c, MSG_TYPE_REG_OK,
                            "Registration successful", 23, zero_key);
        return 0;
    }

    if (f->type == MSG_TYPE_AUTH) {
        if (authenticate_with_frame(c, f) < 0) {
            fprintf(stderr, "[server] Auth failed for %s\n",
                    inet_ntoa(c->addr.sin_addr));
            return -1;
        }
        *auth_done = 1;
    }

    return 0;
}

static int handle_chat_frame(client_state_t *c, const struct chat_frame *f)
{
    struct chat_payload cp;
    uint32_t plain_len = 0;
    char bcast_buf[MAX_USERNAME_LEN + MAX_MSG_LEN + 64];

    if (crypto_aes_decrypt(&c->crypto,
                           c->session_key, f->iv,
                           f->payload, f->payload_len,
                           (uint8_t *)&cp, &plain_len) < 0)
        return -1;

    time_t now = time(NULL);
    char ts[20];
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));

    if (cp.recipient[0]) {
        pthread_mutex_lock(&clients_mutex);
        /* 1. Send to all sessions of the recipient */
        snprintf(bcast_buf, sizeof(bcast_buf),
                 "[%s] (private) %s: %s",
                 ts, c->username, cp.message);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && strcmp(clients[i].username, cp.recipient) == 0) {
                send_frame(&clients[i], MSG_TYPE_CHAT,
                           bcast_buf, (uint16_t)strlen(bcast_buf));
            }
        }

        /* 2. Echo to all sessions of the sender (including self-echo)
         * We exclude the recipient if it happens to be the same user (already handled above) */
        if (strcmp(cp.recipient, c->username) != 0) {
            char echo_buf[MAX_USERNAME_LEN + MAX_MSG_LEN + 64];
            snprintf(echo_buf, sizeof(echo_buf),
                     "[%s] (private to %s) %s: %s",
                     ts, cp.recipient, c->username, cp.message);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].active && strcmp(clients[i].username, c->username) == 0) {
                    send_frame(&clients[i], MSG_TYPE_CHAT,
                               echo_buf, (uint16_t)strlen(echo_buf));
                }
            }
        }
        pthread_mutex_unlock(&clients_mutex);
        return 0;
    }

    snprintf(bcast_buf, sizeof(bcast_buf),
             "[%s] %s: %s", ts, c->username, cp.message);
    printf("%s\n", bcast_buf);
    broadcast_msg(c, bcast_buf, strlen(bcast_buf));
    return 0;
}

static int handle_authenticated_frame(client_state_t *c,
                                      const struct chat_frame *f)
{
    switch (f->type) {
    case MSG_TYPE_CHAT:
        (void)handle_chat_frame(c, f);
        return 0;
    case MSG_TYPE_LIST:
        list_users(c);
        return 0;
    case MSG_TYPE_PASSWD_CHANGE_REQ:
        handle_password_change(c, f);
        return 0;
    case MSG_TYPE_LOGOUT:
        return -1;
    default:
        return 0;
    }
}

static void cleanup_client(client_state_t *c)
{
    char bcast_buf[MAX_USERNAME_LEN + MAX_MSG_LEN + 64];
    char saved_username[64];
    int remaining = 0;
    
    strncpy(saved_username, c->username, sizeof(saved_username));

    pthread_mutex_lock(&clients_mutex);
    c->active = 0;
    if (saved_username[0]) {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && strcmp(clients[i].username, saved_username) == 0) {
                remaining++;
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    if (saved_username[0]) {
        if (remaining == 0) {
            snprintf(bcast_buf, sizeof(bcast_buf),
                     "*** %s left the chat ***", saved_username);
            broadcast_msg(c, bcast_buf, strlen(bcast_buf));
            printf("[server] User '%s' disconnected (last session closed)\n", saved_username);
        } else {
            printf("[server] User '%s' disconnected (%d sessions remain)\n", saved_username, remaining);
        }
        
        /* Always broadcast updated list to everyone */
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && clients[i].username[0]) {
                 list_users_unlocked(&clients[i]);
            }
        }
        pthread_mutex_unlock(&clients_mutex);
    }

    crypto_close(&c->crypto);
    close(c->sock);
    memset(c->username, 0, sizeof(c->username));
    pthread_mutex_destroy(&c->send_mutex);
}

void *client_thread(void *arg)
{
    client_state_t *c = (client_state_t *)arg;
    struct chat_frame f;
    int auth_done = 0;

    if (crypto_open(&c->crypto) < 0) goto done;

    while (running && !auth_done) {
        if (recv_frame(c, &f) < 0) goto done;
        if (handle_pre_auth_frame(c, &f, &auth_done) < 0)
            goto done;
    }

    if (!auth_done)
        goto done;

    announce_join(c);
    
    /* Broadcast list to everyone so sidebars update */
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].username[0]) {
             list_users_unlocked(&clients[i]);
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    while (running) {
        if (recv_frame(c, &f) < 0) break;
        if (handle_authenticated_frame(c, &f) < 0)
            goto done;
    }

done:
    cleanup_client(c);
    return NULL;
}

static void broadcast_msg(client_state_t *sender,
                          const char *msg, size_t msg_len)
{
    (void)sender;
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) continue;
        if (!clients[i].username[0]) continue;
        send_frame(&clients[i], MSG_TYPE_BROADCAST,
                   msg, (uint16_t)msg_len);
    }
    pthread_mutex_unlock(&clients_mutex);
}

static void list_users_unlocked(client_state_t *c)
{
    char buf[1024] = "Online users: ";
    int first = 1;
    char seen[MAX_CLIENTS][MAX_USERNAME_LEN];
    int seen_count = 0;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active || !clients[i].username[0]) continue;

        /* If self: always add (so multiple sessions show up locally) */
        if (strcmp(clients[i].username, c->username) == 0) {
            if (!first) strncat(buf, ", ", sizeof(buf) - strlen(buf) - 1);
            strncat(buf, clients[i].username, sizeof(buf) - strlen(buf) - 1);
            first = 0;
            continue;
        }

        /* If others: only unique names */
        int found = 0;
        for (int j = 0; j < seen_count; j++) {
            if (strcmp(seen[j], clients[i].username) == 0) {
                found = 1; break;
            }
        }
        if (!found) {
            strncpy(seen[seen_count++], clients[i].username, MAX_USERNAME_LEN);
            if (!first) strncat(buf, ", ", sizeof(buf) - strlen(buf) - 1);
            strncat(buf, clients[i].username, sizeof(buf) - strlen(buf) - 1);
            first = 0;
        }
    }

    send_frame(c, MSG_TYPE_SYSTEM, buf, (uint16_t)strlen(buf));
}

static void list_users(client_state_t *c)
{
    pthread_mutex_lock(&clients_mutex);
    list_users_unlocked(c);
    pthread_mutex_unlock(&clients_mutex);
}

static void handle_password_change(client_state_t *c,
                                   const struct chat_frame *f)
{
    struct passwd_change_payload pp;
    uint32_t plain_len = 0;

    if (crypto_aes_decrypt(&c->crypto,
                           c->session_key, f->iv,
                           f->payload, f->payload_len,
                           (uint8_t *)&pp, &plain_len) < 0) {
        send_frame(c, MSG_TYPE_PASSWD_CHANGE_FAIL,
                   "Cannot decode password-change request",
                   (uint16_t)strlen("Cannot decode password-change request"));
        return;
    }

    if (plain_len < sizeof(pp)) {
        send_frame(c, MSG_TYPE_PASSWD_CHANGE_FAIL,
                   "Invalid password-change payload",
                   (uint16_t)strlen("Invalid password-change payload"));
        return;
    }

    if (!user_db_verify(c->username, pp.old_password_hash)) {
        send_frame(c, MSG_TYPE_PASSWD_CHANGE_FAIL,
                   "Old password is incorrect",
                   (uint16_t)strlen("Old password is incorrect"));
        return;
    }

    if (user_db_update_password(c->username, pp.new_password_hash) < 0) {
        send_frame(c, MSG_TYPE_PASSWD_CHANGE_FAIL,
                   "Cannot update password in database",
                   (uint16_t)strlen("Cannot update password in database"));
        return;
    }

    send_frame(c, MSG_TYPE_PASSWD_CHANGE_OK,
               "Password changed successfully",
               (uint16_t)strlen("Password changed successfully"));
}

static int authenticate_with_frame(client_state_t *c,
                                   const struct chat_frame *fixed_f)
{
    struct auth_payload ap;
    uint32_t plain_len = 0;
    int auth_ok;
    const char *ok_msg = "Authentication successful. Welcome!";
    const char *fail_msg = "Authentication failed. Wrong credentials.";

    memset(c->session_key, 0, AES_KEY_SIZE);

    if (crypto_aes_decrypt(&c->crypto,
                           c->session_key, fixed_f->iv,
                           fixed_f->payload, fixed_f->payload_len,
                           (uint8_t *)&ap, &plain_len) < 0)
        return -1;

    if (plain_len < sizeof(struct auth_payload)) return -1;

    ap.username[MAX_USERNAME_LEN - 1] = '\0';
    if (ap.username[0] == '\0')
        return -1;

    auth_ok = user_db_verify(ap.username, ap.password_hash);
    if (auth_ok <= 0) {
        send_frame(c, MSG_TYPE_AUTH_FAIL, fail_msg, (uint16_t)strlen(fail_msg));
        return -1;
    }

    size_t ulen = strnlen(ap.username, MAX_USERNAME_LEN - 1);
    memcpy(c->username, ap.username, ulen);
    c->username[ulen] = '\0';

    crypto_random_bytes(c->session_salt, 16);
    if (crypto_derive_key(&c->crypto, SERVER_SECRET, c->session_salt,
                          c->session_key) < 0)
        return -1;

    uint8_t salt_msg[16 + 64];
    memcpy(salt_msg, c->session_salt, 16);
    snprintf((char *)salt_msg + 16, 64, "%s", ok_msg);

    uint8_t zero_key[AES_KEY_SIZE] = {0};
    uint8_t saved_key[AES_KEY_SIZE];
    memcpy(saved_key, c->session_key, AES_KEY_SIZE);
    memcpy(c->session_key, zero_key, AES_KEY_SIZE);

    send_frame(c, MSG_TYPE_AUTH_OK, salt_msg, 16 + (uint16_t)strlen(ok_msg));

    memcpy(c->session_key, saved_key, AES_KEY_SIZE);

    printf("[server] User '%s' authenticated from %s\n",
           c->username, inet_ntoa(c->addr.sin_addr));
    return 0;
}
