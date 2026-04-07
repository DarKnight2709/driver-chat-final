/* =============================================================================
 * server.c — Multi-client TCP chat server
 *
 * Features:
 *   • SHA-256 password hashing via kernel driver
 *   • AES-256-CBC session-key encryption for all messages
 *   • Per-client session keys derived from shared secret + random salt
 *   • Broadcast + private messages
 *   • Graceful disconnect handling
 *   • Thread-per-client model (up to MAX_CLIENTS)
 * =============================================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sqlite3.h>

#include "crypto_lib.h"

/* ── Config ──────────────────────────────────────────────── */
#define SERVER_PORT     9090
#define MAX_CLIENTS     32
#define BACKLOG         16
#define USER_DB_PATH    "./users.db"

/* Shared server secret — in production, load from secure config */
#define SERVER_SECRET   "CryptoChatServerSecret_v1_DO_NOT_SHARE"

/* ── SQLite user database ────────────────────────────────── */
static sqlite3 *g_user_db = NULL;
static pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── Connected client state ──────────────────────────────── */
typedef struct {
    int      sock;
    int      active;
    char     username[MAX_USERNAME_LEN];
    uint8_t  session_key[AES_KEY_SIZE];
    uint8_t  session_salt[16];
    struct   sockaddr_in addr;
    pthread_t thread;
    crypto_ctx_t crypto;
    pthread_mutex_t send_mutex;
} client_state_t;

static client_state_t clients[MAX_CLIENTS];
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static int server_fd = -1;
static volatile int running = 1;

/* ── Forward declarations ────────────────────────────────── */
static void *client_thread(void *arg);
static int   send_frame   (client_state_t *c, uint8_t type,
                            const void *payload, uint16_t len);
static int   recv_frame   (client_state_t *c, struct chat_frame *f);
static int   authenticate_with_frame(client_state_t *c, struct chat_frame *fixed_f);
static void  broadcast_msg(client_state_t *sender,
                            const char *msg, size_t msg_len);
static void  list_users   (client_state_t *c);
static int   user_db_init (const char *db_path);
static void  user_db_close(void);
static int   user_db_count_users(int *count_out);
static int   user_db_verify(const char *uname,
                            const uint8_t *pwd_hash);
static int   user_db_add  (const char *uname,
                            const uint8_t *pwd_hash);
static int   add_user_db_plain(crypto_ctx_t *ctx,
                            const char *uname, const char *pwd);

/* ── Compute HMAC-SHA256 for frame integrity ─────────────── */
/*
 * compute_frame_hmac - tính giá trị integrity/digest cho một `chat_frame`.
 *
 * Lưu ý: code sử dụng `crypto_sha256` (SHA-256) để tính digest thay vì HMAC chuẩn.
 * Digest được tính từ chuỗi:
 *   type (1 byte) || payload_len (2 bytes) || iv (AES_IV_SIZE) || payload
 *
 * @ctx: ngữ cảnh crypto (chứa fd để gọi driver)
 * @f:   frame dùng để lấy type/payload_len/iv/payload
 * @hmac_out: buffer đích kích thước SHA256_DIGEST_SIZE bytes
 *
 * Giá trị trả về:
 * - 0 khi tính thành công
 * - giá trị âm nếu thất bại (malloc thất bại hoặc ioctl SHA-256 thất bại)
 */
static int compute_frame_hmac(crypto_ctx_t *ctx,
                               const struct chat_frame *f,
                               uint8_t hmac_out[SHA256_DIGEST_SIZE])
{
    /* HMAC input: type (1) + payload_len (2) + iv (16) + payload */
    size_t   buf_len = 1 + 2 + AES_IV_SIZE + f->payload_len;
    uint8_t *buf = malloc(buf_len);
    int      ret;

    if (!buf) return -1;

    buf[0] = f->type;
    buf[1] = (f->payload_len >> 8) & 0xFF;
    buf[2] =  f->payload_len & 0xFF;
    memcpy(buf + 3, f->iv, AES_IV_SIZE);
    memcpy(buf + 3 + AES_IV_SIZE, f->payload, f->payload_len);

    ret = crypto_sha256(ctx, buf, (uint32_t)buf_len, hmac_out);
    free(buf);
    return ret;
}

/* ── Send an encrypted frame to a client ─────────────────── */
/*
 * send_frame - mã hóa payload của một frame rồi gửi tới client.
 *
 * @c:         trạng thái client (chứa sock + session key + mutex gửi)
 * @type:      loại frame (MSG_TYPE_*).
 * @payload:   con trỏ dữ liệu plaintext cần gửi.
 * @plain_len: độ dài plaintext payload.
 *
 * Quy trình:
 * - tạo IV ngẫu nhiên
 * - AES-encrypt payload với `c->session_key`
 * - set f.payload_len
 * - tính digest integrity vào f.hmac
 * - gửi: header (không bao gồm payload) + payload ciphertext
 *
 * Giá trị trả về:
 * - 0 khi send thành công
 * - -1 nếu mã hóa hoặc send() thất bại.
 */
/* ── Send frame with specific key (for pre-auth messages) ──── */
static int send_frame_with_key(client_state_t *c, uint8_t type,
                                const void *payload, uint16_t plain_len,
                                const uint8_t *key)
{
    struct chat_frame f;
    uint32_t cipher_len = 0;
    int ret;

    memset(&f, 0, sizeof(f));
    f.version = PROTO_VERSION;
    f.type    = type;

    crypto_random_bytes(f.iv, AES_IV_SIZE);

    ret = crypto_aes_encrypt(&c->crypto, key, f.iv,
                              (const uint8_t *)payload, plain_len,
                              f.payload, &cipher_len);
    if (ret < 0) return -1;

    f.payload_len = (uint16_t)cipher_len;
    compute_frame_hmac(&c->crypto, &f, f.hmac);

    size_t hdr_size = sizeof(f) - sizeof(f.payload);
    pthread_mutex_lock(&c->send_mutex);
    ssize_t sent = send(c->sock, &f, hdr_size + f.payload_len, MSG_NOSIGNAL);
    pthread_mutex_unlock(&c->send_mutex);
    if (sent < 0)
        return -1;

    return 0;
}

static int send_frame(client_state_t *c, uint8_t type,
                      const void *payload, uint16_t plain_len)
{
    return send_frame_with_key(c, type, payload, plain_len, c->session_key);
}

/* ── Receive and verify a frame ──────────────────────────── */
/*
 * recv_frame - nhận header+payload của frame và kiểm tra integrity.
 *
 * @c: frame đến từ client nào (để dùng crypto ctx và username để log lỗi)
 * @f: buffer frame để ghi kết quả (sau khi nhận xong)
 *
 * Kiểm tra:
 * - version đúng PROTO_VERSION
 * - payload_len hợp lệ (<= MAX_DATA_SIZE)
 * - digest/HMAC khớp với compute_frame_hmac()
 *
 * Giá trị trả về:
 * - 0 khi nhận đủ và digest khớp
 * - -1 nếu recv lỗi/thiếu dữ liệu, version/payload_len sai hoặc digest không khớp.
 */
static int recv_frame(client_state_t *c, struct chat_frame *f)
{
    size_t  hdr_size = sizeof(*f) - sizeof(f->payload);
    ssize_t n;
    uint8_t expected_hmac[SHA256_DIGEST_SIZE];

    /* Receive header first */
    n = recv(c->sock, f, hdr_size, MSG_WAITALL);
    if (n <= 0) return -1;
    if ((size_t)n < hdr_size) return -1;

    if (f->version != PROTO_VERSION) return -1;
    if (f->payload_len > MAX_DATA_SIZE) return -1;

    /* Receive payload */
    if (f->payload_len > 0) {
        n = recv(c->sock, f->payload, f->payload_len, MSG_WAITALL);
        if (n != (ssize_t)f->payload_len) return -1;
    }

    /* Verify HMAC */
    compute_frame_hmac(&c->crypto, f, expected_hmac);
    if (memcmp(expected_hmac, f->hmac, SHA256_DIGEST_SIZE) != 0) {
        fprintf(stderr, "[server] HMAC mismatch from %s — dropping frame\n",
                c->username[0] ? c->username : "unknown");
        return -1;
    }

    return 0;
}

/* ── Authenticate a new connection ───────────────────────── */
/*
 * authenticate - bắt tay xác thực một kết nối mới.
 *
 * @c: trạng thái client (socket, crypto ctx, username/session key sẽ được cập nhật)
 *
 * Quy trình:
 * - khởi tạo session_key = 0 (bootstrap)
 * - nhận frame auth (MSG_TYPE_AUTH)
 * - giải mã frame auth bằng bootstrap key
 * - đối chiếu username + password_hash với `user_db`
 * - nếu thất bại: gửi MSG_TYPE_AUTH_FAIL (bằng zero key)
 * - nếu thành công:
 *   + tạo random session_salt (16 bytes)
 *   + derive session_key = crypto_derive_key(SERVER_SECRET, session_salt)
 *   + gửi MSG_TYPE_AUTH_OK chứa session_salt (truyền bằng zero key trong lần gửi đầu)
 *   + sau đó chuyển sang session key thật
 *
 * Giá trị trả về:
 * - 0 nếu authenticate thành công
 * - -1 nếu sai credentials hoặc recv/decrypt thất bại.
 */
static int authenticate_with_frame(client_state_t *c, struct chat_frame *fixed_f)
{
    struct auth_payload ap;
    uint32_t plain_len = 0;
    int auth_ok;
    const char *ok_msg   = "Authentication successful. Welcome!";
    const char *fail_msg = "Authentication failed. Wrong credentials.";

    /* Receive auth frame (temporarily use a zero session key for bootstrap) */
    memset(c->session_key, 0, AES_KEY_SIZE);

    /* Decrypt with bootstrap zero key */
    if (crypto_aes_decrypt(&c->crypto,
                           c->session_key, fixed_f->iv,
                           fixed_f->payload, fixed_f->payload_len,
                           (uint8_t *)&ap, &plain_len) < 0)
        return -1;

    if (plain_len < sizeof(struct auth_payload)) return -1;

    /* Ensure decrypted username is always a bounded C string. */
    ap.username[MAX_USERNAME_LEN - 1] = '\0';
    if (ap.username[0] == '\0')
        return -1;

    auth_ok = user_db_verify(ap.username, ap.password_hash);
    if (auth_ok <= 0) {
        /* Auth failed — use zero key to send rejection */
        send_frame(c, MSG_TYPE_AUTH_FAIL, fail_msg, (uint16_t)strlen(fail_msg));
        return -1;
    }

    /* Copy username safely and ensure explicit NUL termination. */
    size_t ulen = strnlen(ap.username, MAX_USERNAME_LEN - 1);
    memcpy(c->username, ap.username, ulen);
    c->username[ulen] = '\0';

    /* Derive real session key: SHA256(SERVER_SECRET || client_salt) */
    crypto_random_bytes(c->session_salt, 16);
    crypto_derive_key(&c->crypto, SERVER_SECRET, c->session_salt,
                      c->session_key);

    /* Send session salt so client can derive the same key */
    uint8_t salt_msg[16 + 64];
    memcpy(salt_msg, c->session_salt, 16);
    snprintf((char *)salt_msg + 16, 64, "%s", ok_msg);

    /* Still use zero key to transmit salt, then switch */
    uint8_t zero_key[AES_KEY_SIZE] = {0};
    uint8_t saved_key[AES_KEY_SIZE];
    memcpy(saved_key, c->session_key, AES_KEY_SIZE);
    memcpy(c->session_key, zero_key, AES_KEY_SIZE);

    send_frame(c, MSG_TYPE_AUTH_OK, salt_msg, 16 + (uint16_t)strlen(ok_msg));

    /* Switch to real session key */
    memcpy(c->session_key, saved_key, AES_KEY_SIZE);

    printf("[server] User '%s' authenticated from %s\n",
           c->username, inet_ntoa(c->addr.sin_addr));
    return 0;
}

/* ── Broadcast a message to all authenticated clients ─────── */
/*
 * broadcast_msg - gửi broadcast tới tất cả client đã được authenticate.
 *
 * @sender: client gửi (hiện tại không dùng vì server broadcast cho tất cả)
 * @msg: buffer plaintext message
 * @msg_len: độ dài message
 *
 * Giá trị trả về:
 * - void; thực tế hàm gửi frame MSG_TYPE_BROADCAST cho mọi client active.
 */
static void broadcast_msg(client_state_t *sender,
                           const char *msg, size_t msg_len)
{
    (void)sender; /* intentionally unused */
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) continue;
        if (!clients[i].username[0]) continue;
        send_frame(&clients[i], MSG_TYPE_BROADCAST,
                   msg, (uint16_t)msg_len);
    }
    pthread_mutex_unlock(&clients_mutex);
}

/* ── List online users ───────────────────────────────────── */
/*
 * list_users - xây dựng danh sách username của các client đang active và gửi lại cho một client.
 *
 * @c: client yêu cầu lệnh /list (server sẽ trả về MSG_TYPE_SYSTEM).
 *
 * Giá trị trả về:
 * - void.
 */
static void list_users(client_state_t *c)
{
    char buf[1024] = "Online users: ";
    int  first     = 1;

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active || !clients[i].username[0]) continue;
        if (!first) strncat(buf, ", ", sizeof(buf) - strlen(buf) - 1);
        strncat(buf, clients[i].username, sizeof(buf) - strlen(buf) - 1);
        first = 0;
    }
    pthread_mutex_unlock(&clients_mutex);

    send_frame(c, MSG_TYPE_SYSTEM, buf, (uint16_t)strlen(buf));
}

/* ── Per-client thread ───────────────────────────────────── */
/*
 * client_thread - hàm chạy trong luồng xử lý cho từng client.
 *
 * Nhiệm vụ:
 * - mở crypto ctx riêng cho client
 * - authenticate client
 * - broadcast tin nhắn “joined/left”
 * - vòng lặp nhận frame:
 *   + MSG_TYPE_CHAT: giải mã và broadcast hoặc gửi private message tương ứng cp.recipient
 *   + MSG_TYPE_LIST: trả về danh sách online users
 *   + MSG_TYPE_LOGOUT: kết thúc luồng
 * - cleanup khi rời đi: đặt active = 0, đóng socket, crypto_close, destroy mutex.
 *
 * @arg: con trỏ tới `client_state_t` của luồng.
 *
 * Giá trị trả về:
 * - luôn trả về NULL để thread kết thúc.
 */
static void *client_thread(void *arg)
{
    client_state_t *c = (client_state_t *)arg;
    struct chat_frame f;
    struct chat_payload cp;
    uint32_t plain_len;
    /* Enough space for formatted strings like:
     *   "[%s] %s: %s" and "[%s] (private) %s: %s"
     * where %s fields can be up to their respective fixed limits.
     */
    char bcast_buf[MAX_USERNAME_LEN + MAX_MSG_LEN + 64];

    /* Open private crypto ctx */
    if (crypto_open(&c->crypto) < 0) goto done;

    /* Auth handshake */
    while (running) {
        if (recv_frame(c, &f) < 0) goto done;

        if (f.type == MSG_TYPE_REGISTER) {
            struct auth_payload rp;
            uint32_t plen = 0;
            uint8_t zero_key[AES_KEY_SIZE] = {0};
            int reg_rc;
            if (crypto_aes_decrypt(&c->crypto, zero_key, f.iv,
                                   f.payload, f.payload_len,
                                   (uint8_t *)&rp, &plen) < 0) {
                send_frame_with_key(c, MSG_TYPE_REG_FAIL, "Decrypt error", 13, zero_key);
                continue;
            }

            if (plen < sizeof(struct auth_payload)) {
                send_frame_with_key(c, MSG_TYPE_REG_FAIL, "Invalid payload", 15, zero_key);
                continue;
            }

            rp.username[MAX_USERNAME_LEN - 1] = '\0';
            if (rp.username[0] == '\0') {
                send_frame_with_key(c, MSG_TYPE_REG_FAIL, "Username required", 17, zero_key);
                continue;
            }

            reg_rc = user_db_add(rp.username, rp.password_hash);
            if (reg_rc == 1) {
                send_frame_with_key(c, MSG_TYPE_REG_FAIL, "User already exists", 19, zero_key);
                continue;
            }
            if (reg_rc < 0) {
                send_frame_with_key(c, MSG_TYPE_REG_FAIL, "Database error", 14, zero_key);
                continue;
            }

            printf("[server] New user registered: %s\n", rp.username);
            send_frame_with_key(c, MSG_TYPE_REG_OK, "Registration successful", 23, zero_key);
            continue;
        }

        if (f.type == MSG_TYPE_AUTH) {
            /* Hand off to authenticate function which expects MSG_TYPE_AUTH already received */
            /* We need to 'un-receive' or just pass the frame. 
             * Simplest: modify authenticate to accept the first frame.
             */
            if (authenticate_with_frame(c, &f) < 0) {
                fprintf(stderr, "[server] Auth failed for %s\n",
                        inet_ntoa(c->addr.sin_addr));
                goto done;
            }
            break; /* Auth success, proceed to chat */
        }
        
        /* Ignore other types before auth */
    }

    /* Announce arrival */
    snprintf(bcast_buf, sizeof(bcast_buf),
             "*** %s joined the chat ***", c->username);
    broadcast_msg(c, bcast_buf, strlen(bcast_buf));

    /* Main receive loop */
    while (running) {
        if (recv_frame(c, &f) < 0) break;

        switch (f.type) {
        case MSG_TYPE_CHAT: {
            plain_len = 0;
            if (crypto_aes_decrypt(&c->crypto,
                                   c->session_key, f.iv,
                                   f.payload, f.payload_len,
                                   (uint8_t *)&cp, &plain_len) < 0)
                break;

            /* Timestamp */
            time_t now = time(NULL);
            char ts[20];
            strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));

            if (cp.recipient[0]) {
                /* Private message */
                pthread_mutex_lock(&clients_mutex);
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (!clients[i].active) continue;
                    if (strcmp(clients[i].username, cp.recipient) == 0) {
                        snprintf(bcast_buf, sizeof(bcast_buf),
                                 "[%s] (private) %s: %s",
                                 ts, c->username, cp.message);
                        send_frame(&clients[i], MSG_TYPE_CHAT,
                                   bcast_buf, (uint16_t)strlen(bcast_buf));
                        /* Echo private message back to sender as well.
                         * Server currently delivers private frames only to the recipient,
                         * so we explicitly send the same frame to the sender (c) too.
                         * If sender == recipient, the recipient send above already covers it.
                         */
                        if (strcmp(clients[i].username, c->username) != 0) {
                            send_frame(c, MSG_TYPE_CHAT,
                                       bcast_buf, (uint16_t)strlen(bcast_buf));
                        }
                        break;
                    }
                }
                pthread_mutex_unlock(&clients_mutex);
            } else {
                /* Broadcast */
                snprintf(bcast_buf, sizeof(bcast_buf),
                         "[%s] %s: %s", ts, c->username, cp.message);
                printf("%s\n", bcast_buf);
                broadcast_msg(c, bcast_buf, strlen(bcast_buf));
            }
            break;
        }

        case MSG_TYPE_LIST:
            list_users(c);
            break;

        case MSG_TYPE_LOGOUT:
            goto done;

        default:
            break;
        }
    }

done:
    /* Mark inactive first so no other thread sends to this client */
    pthread_mutex_lock(&clients_mutex);
    c->active = 0;
    pthread_mutex_unlock(&clients_mutex);

    if (c->username[0]) {
        snprintf(bcast_buf, sizeof(bcast_buf),
                 "*** %s left the chat ***", c->username);
        broadcast_msg(c, bcast_buf, strlen(bcast_buf));
        printf("[server] User '%s' disconnected\n", c->username);
    }

    crypto_close(&c->crypto);
    close(c->sock);
    memset(c->username, 0, sizeof(c->username));
    pthread_mutex_destroy(&c->send_mutex);

    return NULL;
}

/* ── SQLite helpers ─────────────────────────────────────── */
static int user_db_init(const char *db_path)
{
    const char *schema_sql =
        "CREATE TABLE IF NOT EXISTS users ("
        "username TEXT PRIMARY KEY,"
        "password_hash BLOB NOT NULL CHECK(length(password_hash)=32),"
        "created_at TEXT NOT NULL DEFAULT (datetime('now'))"
        ");";
    char *errmsg = NULL;

    pthread_mutex_lock(&db_mutex);
    if (sqlite3_open(db_path, &g_user_db) != SQLITE_OK) {
        fprintf(stderr, "[server] sqlite3_open(%s) failed: %s\n",
                db_path, sqlite3_errmsg(g_user_db));
        if (g_user_db) {
            sqlite3_close(g_user_db);
            g_user_db = NULL;
        }
        pthread_mutex_unlock(&db_mutex);
        return -1;
    }

    if (sqlite3_exec(g_user_db, schema_sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "[server] sqlite schema init failed: %s\n",
                errmsg ? errmsg : "unknown error");
        sqlite3_free(errmsg);
        sqlite3_close(g_user_db);
        g_user_db = NULL;
        pthread_mutex_unlock(&db_mutex);
        return -1;
    }

    pthread_mutex_unlock(&db_mutex);
    return 0;
}

static void user_db_close(void)
{
    pthread_mutex_lock(&db_mutex);
    if (g_user_db) {
        sqlite3_close(g_user_db);
        g_user_db = NULL;
    }
    pthread_mutex_unlock(&db_mutex);
}

static int user_db_count_users(int *count_out)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    int count = 0;

    if (!count_out) return -1;

    pthread_mutex_lock(&db_mutex);
    if (!g_user_db) {
        pthread_mutex_unlock(&db_mutex);
        return -1;
    }

    rc = sqlite3_prepare_v2(g_user_db,
                            "SELECT COUNT(*) FROM users;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&db_mutex);
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    } else {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&db_mutex);
        return -1;
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_mutex);
    *count_out = count;
    return 0;
}

static int user_db_verify(const char *uname, const uint8_t *pwd_hash)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    int found = 0;

    if (!uname || !pwd_hash) return 0;

    pthread_mutex_lock(&db_mutex);
    if (!g_user_db) {
        pthread_mutex_unlock(&db_mutex);
        return 0;
    }

    rc = sqlite3_prepare_v2(g_user_db,
                            "SELECT 1 FROM users "
                            "WHERE username = ?1 AND password_hash = ?2 "
                            "LIMIT 1;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&db_mutex);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, uname, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, pwd_hash, SHA256_DIGEST_SIZE, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) found = 1;

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_mutex);
    return found;
}

/* return: 0 created, 1 exists, -1 error */
static int user_db_add(const char *uname, const uint8_t *pwd_hash)
{
    sqlite3_stmt *stmt = NULL;
    int rc;

    if (!uname || !pwd_hash) return -1;

    pthread_mutex_lock(&db_mutex);
    if (!g_user_db) {
        pthread_mutex_unlock(&db_mutex);
        return -1;
    }

    rc = sqlite3_prepare_v2(g_user_db,
                            "INSERT INTO users(username, password_hash) "
                            "VALUES(?1, ?2);",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&db_mutex);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, uname, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, pwd_hash, SHA256_DIGEST_SIZE, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_mutex);

    if (rc == SQLITE_DONE) return 0;
    if (rc == SQLITE_CONSTRAINT || rc == SQLITE_CONSTRAINT_PRIMARYKEY)
        return 1;
    return -1;
}

/* Helper to add user with clear-text password (for initial seed) */
static int add_user_db_plain(crypto_ctx_t *ctx, const char *uname, const char *pwd)
{
    uint8_t hash[SHA256_DIGEST_SIZE];
    crypto_sha256(ctx, (const uint8_t *)pwd, (uint32_t)strlen(pwd), hash);
    return user_db_add(uname, hash);
}

/* ── Signal handler ──────────────────────────────────────── */
/*
 * sig_handler - xử lý tín hiệu dừng (SIGINT/SIGTERM).
 *
 * @sig: số hiệu tín hiệu (không dùng).
 *
 * Tác dụng:
 * - đặt `running = 0` để các vòng lặp accept/receive dừng dần
 * - đóng server_fd nếu đã mở để unblock accept()
 *
 * Giá trị trả về:
 * - void.
 */
static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
    if (server_fd >= 0) close(server_fd);
}

/* ── main ────────────────────────────────────────────────── */
/*
 * main - khởi chạy server:
 * - mở driver kernel `/dev/crypto_chat`
 * - seed DB user mẫu (alice/bob/...)
 * - tạo socket TCP, bind/listen
 * - accept loop: mỗi kết nối tạo một thread `client_thread`
 *
 * @argc/@argv:
 * - argv[1] (nếu có) là port
 *
 * Giá trị trả về:
 * - 0 khi thoát bình thường (do running = 0)
 * - 1 khi gặp lỗi khởi tạo (driver/socket/bind/listen).
 */
int main(int argc, char *argv[])
{
    int port = SERVER_PORT;
    struct sockaddr_in addr;
    crypto_ctx_t init_ctx;
    int loaded_users = 0;

    if (argc >= 2) port = atoi(argv[1]);

    /* Open driver for initial setup */
    if (crypto_open(&init_ctx) < 0) {
        fprintf(stderr, "[server] Cannot open %s — is the driver loaded?\n",
                CRYPTO_CHAT_DEV_PATH);
        return 1;
    }

    if (user_db_init(USER_DB_PATH) < 0) {
        fprintf(stderr, "[server] Cannot initialize SQLite user DB at %s\n",
                USER_DB_PATH);
        crypto_close(&init_ctx);
        return 1;
    }

    /* Seed default users once. INSERT conflict is ignored by user_db_add(). */
    add_user_db_plain(&init_ctx, "alice",   "password123");
    add_user_db_plain(&init_ctx, "bob",     "secret456");
    add_user_db_plain(&init_ctx, "charlie", "hello789");
    add_user_db_plain(&init_ctx, "admin",   "admin@CryptoChat#2024");
    if (user_db_count_users(&loaded_users) == 0) {
        printf("[server] %d users loaded from SQLite (%s)\n",
               loaded_users, USER_DB_PATH);
    }
    crypto_close(&init_ctx);

    /* TCP socket */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(server_fd, BACKLOG) < 0) {
        perror("listen"); return 1;
    }

    printf("[server] CryptoChat server listening on port %d\n", port);
    printf("[server] Encryption: AES-256-CBC | Hash: SHA-256 (kernel driver)\n");
    printf("[server] Press Ctrl-C to stop\n\n");

    /* Accept loop */
    while (running) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int cli_fd = accept(server_fd,
                            (struct sockaddr *)&cli_addr, &cli_len);
        if (cli_fd < 0) {
            if (running) perror("accept");
            break;
        }

        /* Find free slot */
        pthread_mutex_lock(&clients_mutex);
        int slot = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i].active) { slot = i; break; }
        }

        if (slot < 0) {
            pthread_mutex_unlock(&clients_mutex);
            fprintf(stderr, "[server] Max clients reached\n");
            close(cli_fd);
            continue;
        }

        memset(&clients[slot], 0, sizeof(clients[slot]));
        clients[slot].sock   = cli_fd;
        clients[slot].active = 1;
        clients[slot].addr   = cli_addr;
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
    /* Close all client sockets */
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) close(clients[i].sock);
    }
    pthread_mutex_unlock(&clients_mutex);

    user_db_close();
    return 0;
}
