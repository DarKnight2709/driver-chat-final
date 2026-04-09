/* =============================================================================
 * network.c — Networking, encryption, authentication & background threads
 * ============================================================================= */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "../include/app_state.h"

/* ── Internal forward declarations ───────────────────────── */
static int connect_to_server(const char *host, int port);
static int recv_frame_gui(struct chat_frame *f);
static int frame_hmac(const struct chat_frame *f,
                      uint8_t hmac_out[SHA256_DIGEST_SIZE]);
static int do_auth(const char *username, const char *password);
static void *recv_thread_func(void *data);


/* ═══════════════════════════════════════════════════════════
 * Tier 5 — Supporting core logic (integrity hash)
 * ═══════════════════════════════════════════════════════════ */

static int frame_hmac(const struct chat_frame *f,
                      uint8_t hmac_out[SHA256_DIGEST_SIZE])
{
    size_t   buf_len = 1 + 2 + AES_IV_SIZE + f->payload_len;
    uint8_t *buf = malloc(buf_len);
    int      ret;
    if (!buf) return -1;

    buf[0] = f->type;
    buf[1] = (f->payload_len >> 8) & 0xFF;
    buf[2] =  f->payload_len       & 0xFF;
    memcpy(buf + 3,              f->iv,      AES_IV_SIZE);
    memcpy(buf + 3 + AES_IV_SIZE, f->payload, f->payload_len);

    ret = crypto_sha256(&app.crypto, buf, (uint32_t)buf_len, hmac_out);
    free(buf);
    return ret;
}


/* ═══════════════════════════════════════════════════════════
 * Tier 2 — Protocol / transport layer
 * ═══════════════════════════════════════════════════════════ */

int send_command(uint8_t type, const void *payload, uint16_t plain_len)
{
    struct chat_frame f;
    uint32_t cipher_len = 0;

    memset(&f, 0, sizeof(f));
    f.version = PROTO_VERSION;
    f.type    = type;
    crypto_random_bytes(f.iv, AES_IV_SIZE);

    if (crypto_aes_encrypt(&app.crypto,
                            app.session_key, f.iv,
                            (const uint8_t *)payload, plain_len,
                            f.payload, &cipher_len) < 0)
        return -1;

    f.payload_len = (uint16_t)cipher_len;
    frame_hmac(&f, f.hmac);

    size_t hdr_size = sizeof(f) - sizeof(f.payload);
    if (send(app.sock, &f, hdr_size + f.payload_len, MSG_NOSIGNAL) < 0) {
        g_print("[send_command] send failed for type %d\n", type);
        return -1;
    }
    g_print("[send_command] sent frame type %d, payload_len %d\n", type, f.payload_len);
    return 0;
}

static int recv_frame_gui(struct chat_frame *f)
{
    size_t  hdr_size = sizeof(*f) - sizeof(f->payload);
    ssize_t n;
    uint8_t expected[SHA256_DIGEST_SIZE];

    n = recv(app.sock, f, hdr_size, MSG_WAITALL);
    if (n <= 0) {
        g_print("[recv_frame_gui] recv header failed: n=%ld\n", n);
        return -1;
    }
    if ((size_t)n < hdr_size) {
        g_print("[recv_frame_gui] incomplete header: got %ld bytes, expected %zu\n", n, hdr_size);
        return -1;
    }
    if (f->version != PROTO_VERSION || f->payload_len > MAX_DATA_SIZE) {
        g_print("[recv_frame_gui] invalid version (%d) or payload_len (%d)\n", f->version, f->payload_len);
        return -1;
    }

    if (f->payload_len > 0) {
        n = recv(app.sock, f->payload, f->payload_len, MSG_WAITALL);
        if (n != (ssize_t)f->payload_len) {
            g_print("[recv_frame_gui] incomplete payload: got %ld bytes, expected %d\n", n, f->payload_len);
            return -1;
        }
    }

    frame_hmac(f, expected);
    if (memcmp(expected, f->hmac, SHA256_DIGEST_SIZE) != 0) {
        g_print("[recv_frame_gui] HMAC mismatch\n");
        return -1;
    }
    return 0;
}


/* ═══════════════════════════════════════════════════════════
 * Tier 1 — Real-time behaviour
 * ═══════════════════════════════════════════════════════════ */

static int connect_to_server(const char *host, int port)
{
    struct sockaddr_in addr;
    struct hostent    *he;

    app.sock = socket(AF_INET, SOCK_STREAM, 0);
    if (app.sock < 0) return -1;

    he = gethostbyname(host);
    if (!he) { close(app.sock); app.sock = -1; return -1; }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(app.sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(app.sock);
        app.sock = -1;
        return -1;
    }
    return 0;
}

static void *recv_thread_func(void *data)
{
    (void)data;
    struct chat_frame f;
    uint8_t  plain[MAX_DATA_SIZE + 1];
    uint32_t plain_len;

    send_command(MSG_TYPE_LIST, "", 0);

    while (app.connected) {
        if (recv_frame_gui(&f) < 0) {
            if (app.connected)
                g_idle_add(ui_on_disconnect, NULL);
            app.connected = 0;
            break;
        }

        plain_len = 0;
        if (crypto_aes_decrypt(&app.crypto,
                               app.session_key, f.iv,
                               f.payload, f.payload_len,
                               plain, &plain_len) < 0)
            continue;

        plain[plain_len] = '\0';
        char *text = (char *)plain;

        int msg_type = UI_MSG_NORMAL;
        char *peer = NULL;

        if (f.type == MSG_TYPE_PASSWD_CHANGE_OK)
            msg_type = UI_MSG_PASSWD_OK;
        else if (f.type == MSG_TYPE_PASSWD_CHANGE_FAIL)
            msg_type = UI_MSG_PASSWD_FAIL;
        else if (strncmp(text, "***", 3) == 0)
            msg_type = UI_MSG_SYSTEM;
        else if (strncmp(text, "Online users:", 13) == 0)
            msg_type = UI_MSG_USERLIST;
        else {
            char *p_to = strstr(text, "(private to ");
            if (p_to) {
                /* Echo of my sent message: parse recipient and strip tag */
                msg_type = UI_MSG_PRIVATE;
                const char *start = p_to + 12;
                const char *end = strchr(start, ')');
                if (end && end > start) {
                    peer = g_strndup(start, (gsize)(end - start));
                    /* Strip "(private to recipient) " */
                    size_t tag_total = (size_t)(end - p_to + 1);
                    if (*(end + 1) == ' ') tag_total++;
                    memmove(p_to, p_to + tag_total, strlen(p_to + tag_total) + 1);
                }
            } else {
                char *p_priv = strstr(text, "(private) ");
                if (p_priv) {
                    /* Incoming message: parse sender and strip tag */
                    msg_type = UI_MSG_PRIVATE;
                    char *after = p_priv + 10;
                    char *colon = strstr(after, ": ");
                    if (colon && colon > after) {
                        peer = g_strndup(after, (gsize)(colon - after));
                    }
                    /* Strip "(private) " */
                    memmove(p_priv, p_priv + 10, strlen(p_priv + 10) + 1);
                }
            }
        }

        UIMsgData *d = g_new(UIMsgData, 1);
        d->type = msg_type;
        d->text = g_strdup(text);
        d->peer = peer;  /* NULL for public, "username" for private */
        g_idle_add(ui_on_message, d);

        if (msg_type == UI_MSG_SYSTEM &&
            (strstr(text, "joined") || strstr(text, "left")))
            send_command(MSG_TYPE_LIST, "", 0);
    }
    return NULL;
}

int send_chat(const char *recipient, const char *message)
{
    struct chat_payload cp;
    memset(&cp, 0, sizeof(cp));
    snprintf(cp.sender, sizeof(cp.sender), "%s", app.username);
    snprintf(cp.recipient, sizeof(cp.recipient), "%s", recipient);
    snprintf(cp.message, sizeof(cp.message), "%s", message);
    cp.timestamp = (uint64_t)time(NULL);
    return send_command(MSG_TYPE_CHAT, &cp, sizeof(cp));
}


/* ═══════════════════════════════════════════════════════════
 * Tier 3 — Session / authentication logic
 * ═══════════════════════════════════════════════════════════ */

static int do_auth(const char *username, const char *password)
{
    struct auth_payload ap;
    struct chat_frame   f;
    uint8_t zero_key[AES_KEY_SIZE] = {0};
    uint32_t plain_len = 0;
    uint8_t  plain_buf[MAX_DATA_SIZE];

    memset(&ap, 0, sizeof(ap));
    snprintf(ap.username, sizeof(ap.username), "%s", username);

    if (crypto_sha256(&app.crypto,
                      (const uint8_t *)password, (uint32_t)strlen(password),
                      ap.password_hash) < 0)
        return -1;

    memcpy(app.session_key, zero_key, AES_KEY_SIZE);
    if (send_command(MSG_TYPE_AUTH, &ap, sizeof(ap)) < 0) return -1;
    if (recv_frame_gui(&f) < 0) return -1;

    if (crypto_aes_decrypt(&app.crypto, zero_key, f.iv,
                           f.payload, f.payload_len,
                           plain_buf, &plain_len) < 0)
        return -1;

    if (f.type == MSG_TYPE_AUTH_FAIL) return -1;
    if (f.type != MSG_TYPE_AUTH_OK || plain_len < 16) return -1;

    uint8_t session_salt[16];
    memcpy(session_salt, plain_buf, 16);

    if (crypto_derive_key(&app.crypto, SHARED_SECRET, session_salt,
                          app.session_key) < 0)
        return -1;

    memcpy(app.current_password_hash, ap.password_hash, SHA256_DIGEST_SIZE);
    app.has_password_hash = 1;
    snprintf(app.username, sizeof(app.username), "%s", username);
    return 0;
}

void *connect_thread_func(void *data)
{
    ConnectArgs *args = data;

    if (crypto_open(&app.crypto) < 0) {
        g_idle_add(ui_connect_fail,
                   g_strdup("Cannot open /dev/crypto_chat \xe2\x80\x94 "
                            "is the driver loaded?"));
        g_free(args);
        return NULL;
    }

    if (connect_to_server(args->host, args->port) < 0) {
        crypto_close(&app.crypto);
        char *msg = g_strdup_printf("Cannot connect to %s:%d",
                                    args->host, args->port);
        g_idle_add(ui_connect_fail, msg);
        g_free(args);
        return NULL;
    }

    if (do_auth(args->username, args->password) < 0) {
        close(app.sock); app.sock = -1;
        crypto_close(&app.crypto);
        g_idle_add(ui_connect_fail,
                   g_strdup("Authentication failed \xe2\x80\x94 "
                            "wrong credentials?"));
        g_free(args);
        return NULL;
    }

    app.connected = 1;
    app.reconnecting = 0;
    
    /* Save info for auto-reconnect */
    snprintf(app.last_host, sizeof(app.last_host), "%s", args->host);
    app.last_port = args->port;
    snprintf(app.last_pass, sizeof(app.last_pass), "%s", args->password);

    pthread_create(&app.rx_tid, NULL, recv_thread_func, NULL);

    queue_server_history(args->host, args->port);

    char *host_info = g_strdup_printf("%s:%d", args->host, args->port);
    g_idle_add(ui_connect_ok, host_info);

    g_free(args);
    return NULL;
}

void *signup_thread_func(void *data)
{
    ConnectArgs *args = data;
    struct chat_frame f;
    struct auth_payload ap;
    uint8_t zero_key[AES_KEY_SIZE] = {0};

    if (crypto_open(&app.crypto) < 0) {
        g_idle_add(ui_connect_fail, g_strdup("Cannot open driver"));
        g_free(args); return NULL;
    }

    if (connect_to_server(args->host, args->port) < 0) {
        crypto_close(&app.crypto);
        g_idle_add(ui_connect_fail, g_strdup("Connection failed"));
        g_free(args); return NULL;
    }
    g_print("[SIGNUP] Connected to %s:%d\n", args->host, args->port);

    memset(&ap, 0, sizeof(ap));
    snprintf(ap.username, sizeof(ap.username), "%s", args->username);
    g_print("[SIGNUP] Hashing password\n");
    if (crypto_sha256(&app.crypto,
                      (const uint8_t *)args->password,
                      (uint32_t)strlen(args->password),
                      ap.password_hash) < 0) {
        close(app.sock);
        crypto_close(&app.crypto);
        g_print("[SIGNUP] crypto_sha256 failed\n");
        g_idle_add(ui_connect_fail, g_strdup("Password hashing failed"));
        g_free(args);
        return NULL;
    }

    memcpy(app.session_key, zero_key, AES_KEY_SIZE);
    g_print("[SIGNUP] About to send MSG_TYPE_REGISTER (type=%d) with payload size %zu\n",
            MSG_TYPE_REGISTER, sizeof(ap));

    if (send_command(MSG_TYPE_REGISTER, &ap, sizeof(ap)) < 0) {
        close(app.sock); crypto_close(&app.crypto);
        g_print("[SIGNUP] send_command failed\n");
        g_idle_add(ui_connect_fail, g_strdup("Send failed"));
        g_free(args); return NULL;
    }
    g_print("[SIGNUP] Sent registration request for user: %s\n", args->username);

    if (recv_frame_gui(&f) < 0) {
        close(app.sock); crypto_close(&app.crypto);
        g_print("[SIGNUP] recv_frame_gui failed\n");
        g_idle_add(ui_connect_fail, g_strdup("No response from server"));
        g_free(args); return NULL;
    }
    g_print("[SIGNUP] Received response, frame type: %d\n", f.type);

    if (f.type == MSG_TYPE_REG_OK) {
        queue_server_history(args->host, args->port);
        g_idle_add(ui_connect_success, g_strdup("Sign up successful! Please connect."));
    } else {
        /* Decode error message if any */
        uint32_t plen = 0;
        uint8_t plain[MAX_DATA_SIZE];
        if (crypto_aes_decrypt(&app.crypto, zero_key, f.iv,
                               f.payload, f.payload_len,
                               plain, &plen) < 0) {
            g_idle_add(ui_connect_fail,
                       g_strdup("Sign up failed (cannot decode server response)"));
            close(app.sock);
            crypto_close(&app.crypto);
            g_free(args);
            return NULL;
        }
        if (plen >= MAX_DATA_SIZE) plen = MAX_DATA_SIZE - 1;
        plain[plen] = '\0';
        g_idle_add(ui_connect_fail, g_strdup_printf("Sign up failed: %s", (char*)plain));
    }

    close(app.sock);
    crypto_close(&app.crypto);
    g_free(args);
    return NULL;
}
