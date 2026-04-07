/* =============================================================================
 * client.c — Interactive chat client
 *
 * Features:
 *   • Password hashing via kernel driver (SHA-256) before sending
 *   • Session-key negotiation (PBKDF2-like via driver)
 *   • AES-256-CBC message encryption/decryption via kernel driver
 *   • Receiver thread + main input thread
 *   • Commands: /list, /msg <user> <text>, /quit
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
#include <pthread.h>
#include <time.h>
#include <termios.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "crypto_lib.h"

/* ── Config ──────────────────────────────────────────────── */
#define DEFAULT_HOST    "127.0.0.1"
#define DEFAULT_PORT    9090
#define SHARED_SECRET   "CryptoChatServerSecret_v1_DO_NOT_SHARE"

/* ── Client state ────────────────────────────────────────── */
static struct {
    int          sock;
    char         username[MAX_USERNAME_LEN];
    uint8_t      session_key[AES_KEY_SIZE];
    crypto_ctx_t crypto;
    volatile int running;
} g;

/* ── Forward declarations ────────────────────────────────── */
static int  connect_to_server(const char *host, int port);
static int  do_auth(const char *username, const char *password);
static int  send_chat(const char *recipient, const char *message);
static int  send_command(uint8_t type, const void *payload, uint16_t len);
static int  recv_frame_client(struct chat_frame *f);
static void *recv_thread(void *arg);
static void  read_password(const char *prompt, char *buf, size_t maxlen);
static void  print_help(void);

/* ── Compute HMAC for frame (mirrors server logic) ──────── */
/*
 * frame_hmac - tính giá trị toàn vẹn (integrity) cho một `chat_frame`.
 * Dù tên hàm là HMAC, code hiện tại thực hiện bằng SHA-256:
 * SHA256(type || payload_len || iv || payload).
 *
 * @f: frame cần tính (sử dụng f->type, f->payload_len, f->iv, f->payload).
 * @hmac_out: buffer kết quả, kích thước SHA256_DIGEST_SIZE bytes.
 *
 * Giá trị trả về:
 * - 0 khi thành công
 * - -1 nếu không cấp phát được bộ nhớ tạm hoặc gọi SHA-256 thất bại.
 */
static int frame_hmac(const struct chat_frame *f,
                      uint8_t hmac_out[SHA256_DIGEST_SIZE])
{
    size_t   buf_len = 1 + 2 + AES_IV_SIZE + f->payload_len;
    uint8_t *buf = malloc(buf_len);
    int      ret;

    if (!buf) return -1;

    buf[0] = f->type;
    buf[1] = (f->payload_len >> 8) & 0xFF;
    buf[2] =  f->payload_len & 0xFF;
    memcpy(buf + 3, f->iv, AES_IV_SIZE);
    memcpy(buf + 3 + AES_IV_SIZE, f->payload, f->payload_len);

    ret = crypto_sha256(&g.crypto, buf, (uint32_t)buf_len, hmac_out);
    free(buf);
    return ret;
}

/* ── Send an encrypted frame to server ──────────────────── */
/*
 * send_command - mã hóa payload bằng AES-256-CBC (session key) và gửi frame
 * sang server qua TCP.
 *
 * @type: loại frame (MSG_TYPE_*).
 * @payload: dữ liệu plaintext sẽ được mã hóa.
 * @plain_len: độ dài plaintext.
 *
 * Hành vi:
 * - Tạo IV ngẫu nhiên cho mỗi frame.
 * - Set f.payload_len bằng kích thước ciphertext.
 * - Tính giá trị integrity/digest cho frame rồi gửi (header + payload).
 *
 * Giá trị trả về:
 * - 0 khi gửi thành công
 * - -1 khi mã hóa hoặc gửi lỗi.
 */
static int send_command(uint8_t type, const void *payload, uint16_t plain_len)
{
    struct chat_frame f;
    uint32_t cipher_len = 0;
    int ret;

    memset(&f, 0, sizeof(f));
    f.version = PROTO_VERSION;
    f.type    = type;
    crypto_random_bytes(f.iv, AES_IV_SIZE);

    ret = crypto_aes_encrypt(&g.crypto,
                              g.session_key, f.iv,
                              (const uint8_t *)payload, plain_len,
                              f.payload, &cipher_len);
    if (ret < 0) return -1;

    f.payload_len = (uint16_t)cipher_len;
    frame_hmac(&f, f.hmac);

    size_t hdr_size = sizeof(f) - sizeof(f.payload);
    if (send(g.sock, &f, hdr_size + f.payload_len, MSG_NOSIGNAL) < 0) {
        perror("send");
        return -1;
    }
    return 0;
}

/* ── Receive a frame from server ─────────────────────────── */
/*
 * recv_frame_client - nhận frame từ server và kiểm tra tính hợp lệ.
 *
 * @f: buffer frame để ghi nhận dữ liệu (sẽ chứa cả payload nếu có).
 *
 * Kiểm tra:
 * - f->version trùng PROTO_VERSION
 * - f->payload_len không vượt MAX_DATA_SIZE
 * - digest/HMAC khớp (phát hiện message bị sửa/chèn dữ liệu)
 *
 * Giá trị trả về:
 * - 0 khi nhận đủ dữ liệu và digest khớp
 * - -1 khi recv() lỗi/thiếu dữ liệu, version/payload_len không hợp lệ
 *   hoặc digest không khớp.
 */
static int recv_frame_client(struct chat_frame *f)
{
    size_t  hdr_size = sizeof(*f) - sizeof(f->payload);
    ssize_t n;
    uint8_t expected_hmac[SHA256_DIGEST_SIZE];

    n = recv(g.sock, f, hdr_size, MSG_WAITALL);
    if (n <= 0) return -1;
    if ((size_t)n < hdr_size) return -1;

    if (f->version != PROTO_VERSION || f->payload_len > MAX_DATA_SIZE)
        return -1;

    if (f->payload_len > 0) {
        n = recv(g.sock, f->payload, f->payload_len, MSG_WAITALL);
        if (n != (ssize_t)f->payload_len) return -1;
    }

    frame_hmac(f, expected_hmac);
    if (memcmp(expected_hmac, f->hmac, SHA256_DIGEST_SIZE) != 0) {
        fprintf(stderr, "\n[!] HMAC verification failed — message tampered?\n");
        return -1;
    }

    return 0;
}

/* ── Authentication handshake ────────────────────────────── */
/*
 * do_auth - bắt tay xác thực với server để thiết lập `g.session_key`.
 *
 * Quy trình:
 * 1) SHA-256 password qua kernel driver để tạo ap.password_hash
 * 2) gửi frame MSG_TYPE_AUTH được mã hóa bằng bootstrap key = {0}
 * 3) nhận phản hồi, giải mã bằng bootstrap key
 * 4) nếu OK: lấy 16 bytes salt từ response và derive session key từ SHARED_SECRET
 *
 * @username: tên đăng nhập (đưa vào auth_payload)
 * @password: mật khẩu dạng chuỗi (được băm trước khi gửi)
 *
 * Side effects:
 * - Khi thành công: g.session_key và g.username được cập nhật.
 *
 * Giá trị trả về:
 * - 0 khi auth thành công
 * - -1 khi auth fail hoặc bất kỳ bước nào lỗi.
 */
static int do_auth(const char *username, const char *password)
{
    struct auth_payload ap;
    struct chat_frame   f;
    uint8_t zero_key[AES_KEY_SIZE] = {0};
    uint32_t plain_len = 0;
    uint8_t  plain_buf[MAX_DATA_SIZE];

    /* Step 1: Build auth payload */
    memset(&ap, 0, sizeof(ap));
    snprintf(ap.username, sizeof(ap.username), "%s", username);

    /* SHA-256 the password via kernel driver */
    if (crypto_sha256(&g.crypto,
                      (const uint8_t *)password, (uint32_t)strlen(password),
                      ap.password_hash) < 0) {
        fprintf(stderr, "[client] SHA-256 failed\n");
        return -1;
    }

    /* Step 2: Send auth frame encrypted with bootstrap zero key */
    memcpy(g.session_key, zero_key, AES_KEY_SIZE);

    if (send_command(MSG_TYPE_AUTH, &ap, sizeof(ap)) < 0) return -1;

    /* Step 3: Receive server response */
    if (recv_frame_client(&f) < 0) return -1;

    /* Decrypt with zero key */
    if (crypto_aes_decrypt(&g.crypto,
                           zero_key, f.iv,
                           f.payload, f.payload_len,
                           plain_buf, &plain_len) < 0)
        return -1;

    if (f.type == MSG_TYPE_AUTH_FAIL) {
        plain_buf[plain_len] = '\0';
        fprintf(stderr, "[server] %s\n", plain_buf);
        return -1;
    }

    if (f.type != MSG_TYPE_AUTH_OK || plain_len < 16) {
        fprintf(stderr, "[client] Unexpected auth response\n");
        return -1;
    }

    /* Step 4: Extract session salt (first 16 bytes) and derive session key */
    uint8_t session_salt[16];
    memcpy(session_salt, plain_buf, 16);

    if (crypto_derive_key(&g.crypto, SHARED_SECRET, session_salt,
                          g.session_key) < 0) {
        fprintf(stderr, "[client] Key derivation failed\n");
        return -1;
    }

    printf("[client] %s\n", (char *)plain_buf + 16);
    printf("[client] Session key established (AES-256-CBC)\n");
    snprintf(g.username, sizeof(g.username), "%s", username);
    return 0;
}

/* ── Send a chat message ─────────────────────────────────── */
/*
 * send_chat - đóng gói payload chat (chat_payload) và gửi lên server.
 *
 * @recipient: người nhận; nếu rỗng ("") thì server hiểu là broadcast.
 * @message: nội dung tin nhắn.
 *
 * Giá trị trả về:
 * - 0 nếu frame gửi thành công
 * - -1 nếu gửi thất bại.
 */
static int send_chat(const char *recipient, const char *message)
{
    struct chat_payload cp;
    memset(&cp, 0, sizeof(cp));

    snprintf(cp.sender, sizeof(cp.sender), "%s", g.username);
    snprintf(cp.recipient, sizeof(cp.recipient), "%s", recipient);
    snprintf(cp.message, sizeof(cp.message), "%s", message);
    cp.timestamp = (uint64_t)time(NULL);

    return send_command(MSG_TYPE_CHAT, &cp, sizeof(cp));
}

/* ── Receiver thread (prints incoming messages) ──────────── */
/*
 * recv_thread - luồng nhận message từ server và in ra terminal.
 *
 * Hoạt động:
 * - lặp đến khi g.running = 0
 * - nhận frame (header + payload) và kiểm tra digest
 * - giải mã payload bằng AES-256-CBC session key
 * - in message ra màn hình theo dạng prompt mới
 *
 * @arg: không sử dụng
 *
 * Giá trị trả về:
 * - luôn trả về NULL; kết thúc khi xảy ra lỗi kết nối hoặc g.running = 0.
 */
static void *recv_thread(void *arg)
{
    (void)arg;
    struct chat_frame f;
    uint8_t plain_buf[MAX_DATA_SIZE + 1];
    uint32_t plain_len;

    while (g.running) {
        if (recv_frame_client(&f) < 0) {
            if (g.running)
                printf("\n[!] Connection lost\n");
            g.running = 0;
            break;
        }

        plain_len = 0;
        if (crypto_aes_decrypt(&g.crypto,
                               g.session_key, f.iv,
                               f.payload, f.payload_len,
                               plain_buf, &plain_len) < 0)
            continue;

        plain_buf[plain_len] = '\0';

        /* Print with a fresh prompt line */
        printf("\r\033[K%s\n> ", (char *)plain_buf);
        fflush(stdout);
    }

    return NULL;
}

/* ── Read password without echo ──────────────────────────── */
/*
 * read_password - đọc password từ stdin nhưng tắt echo để không hiển thị ký tự.
 *
 * @prompt: chuỗi hiển thị trước khi đọc
 * @buf: buffer lưu kết quả
 * @maxlen: kích thước tối đa của buffer
 *
 * Giá trị trả về:
 * - void; ghi dữ liệu vào @buf và luôn NUL-terminate.
 */
static void read_password(const char *prompt, char *buf, size_t maxlen)
{
    struct termios old, noecho;

    printf("%s", prompt);
    fflush(stdout);

    tcgetattr(STDIN_FILENO, &old);
    noecho = old;
    noecho.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    tcsetattr(STDIN_FILENO, TCSANOW, &noecho);

    fgets(buf, (int)maxlen, stdin);
    buf[strcspn(buf, "\n")] = '\0';

    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    printf("\n");
}

/*
 * print_help - in ra danh sách lệnh hỗ trợ của client.
 */
static void print_help(void)
{
    printf("Commands:\n");
    printf("  /list              — list online users\n");
    printf("  /msg <user> <text> — private message\n");
    printf("  /quit              — disconnect\n");
    printf("  <text>             — broadcast to all\n\n");
}

/* ── Connect to server ───────────────────────────────────── */
/*
 * connect_to_server - tạo socket TCP và kết nối đến host:port.
 *
 * @host: hostname hoặc IP của server
 * @port: cổng TCP
 *
 * Side effects:
 * - ghi socket fd vào g.sock
 *
 * Giá trị trả về:
 * - 0 khi kết nối thành công
 * - -1 khi socket/resolve/connect thất bại.
 */
static int connect_to_server(const char *host, int port)
{
    struct sockaddr_in addr;
    struct hostent    *he;

    g.sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g.sock < 0) { perror("socket"); return -1; }

    he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "gethostbyname(%s) failed\n", host);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(g.sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return -1;
    }

    printf("[client] Connected to %s:%d\n", host, port);
    return 0;
}

/* ── main ────────────────────────────────────────────────── */
/*
 * main - điểm vào chương trình client:
 * - mở driver kernel /dev/crypto_chat
 * - lấy username/password từ người dùng
 * - kết nối server và thực hiện do_auth để thiết lập session key
 * - chạy receiver thread và vòng lặp nhập lệnh chat
 *
 * Giá trị trả về:
 * - 0 khi thoát bình thường
 * - 1 khi gặp lỗi ở các bước khởi tạo/kết nối/auth.
 */
int main(int argc, char *argv[])
{
    const char *host     = DEFAULT_HOST;
    int         port     = DEFAULT_PORT;
    char        username[MAX_USERNAME_LEN];
    char        password[MAX_PASSWORD_LEN];
    char        line[MAX_MSG_LEN + MAX_USERNAME_LEN + 8];
    pthread_t   rx_tid;

    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = atoi(argv[2]);

    printf("==============================================\n");
    printf("   CryptoChat Client — AES-256 + SHA-256\n");
    printf("   Kernel driver: %s\n", CRYPTO_CHAT_DEV_PATH);
    printf("==============================================\n\n");

    /* Open kernel crypto driver */
    if (crypto_open(&g.crypto) < 0) {
        fprintf(stderr, "[client] Cannot open %s — driver loaded?\n",
                CRYPTO_CHAT_DEV_PATH);
        return 1;
    }

    /* Credentials */
    printf("Username: ");
    fflush(stdout);
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = '\0';

    read_password("Password: ", password, sizeof(password));

    /* Connect */
    if (connect_to_server(host, port) < 0) {
        crypto_close(&g.crypto);
        return 1;
    }

    /* Auth */
    if (do_auth(username, password) < 0) {
        close(g.sock);
        crypto_close(&g.crypto);
        return 1;
    }

    print_help();
    g.running = 1;

    /* Start receiver thread */
    pthread_create(&rx_tid, NULL, recv_thread, NULL);

    /* Input loop */
    while (g.running) {
        printf("> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\n")] = '\0';
        if (!line[0]) continue;

        if (strcmp(line, "/quit") == 0) {
            send_command(MSG_TYPE_LOGOUT, "bye", 3);
            break;

        } else if (strcmp(line, "/list") == 0) {
            send_command(MSG_TYPE_LIST, "", 0);

        } else if (strncmp(line, "/msg ", 5) == 0) {
            char *rest = line + 5;
            char *sp   = strchr(rest, ' ');
            if (!sp) {
                printf("Usage: /msg <user> <message>\n");
            } else {
                *sp = '\0';
                send_chat(rest, sp + 1);
            }

        } else if (line[0] == '/') {
            printf("Unknown command. ");
            print_help();

        } else {
            send_chat("" /* broadcast */, line);
        }
    }

    g.running = 0;
    shutdown(g.sock, SHUT_RDWR);
    close(g.sock);
    pthread_join(rx_tid, NULL);
    crypto_close(&g.crypto);

    printf("[client] Disconnected. Goodbye!\n");
    return 0;
}
