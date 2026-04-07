/* =============================================================================
 * gui_client.c — GTK3 GUI Chat Client cho CryptoChat
 *
 * Tính năng:
 *   • Trang đăng nhập với các trường server/thông tin xác thực
 *   • Chat thời gian thực với màu sắc phân loại tin nhắn
 *   • Sidebar danh sách người dùng trực tuyến (tự động làm mới)
 *   • Nhắn tin riêng tư bằng cách nhấp đúp vào người dùng
 *   • Mã hóa AES-256-CBC thông qua kernel driver
 *   • Giao diện tối với bảng màu lấy cảm hứng từ Catppuccin
 *
 * Build:  make gui_client          (yêu cầu gtk3-devel)
 * Chạy:   ./gui_client [host] [port]
 * ============================================================================= */

#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <pango/pango.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "crypto_lib.h"

/* ── Cấu hình ────────────────────────────────────────────── */
#define DEFAULT_HOST  "127.0.0.1"
#define DEFAULT_PORT  "9090"
#define SHARED_SECRET "CryptoChatServerSecret_v1_DO_NOT_SHARE"
#define LIST_INTERVAL_SEC 15

/* ── Loại tin nhắn UI (nội bộ) ───────────────────────────── */
enum {
    UI_MSG_NORMAL,
    UI_MSG_SYSTEM,
    UI_MSG_PRIVATE,
    UI_MSG_ERROR,
    UI_MSG_USERLIST
};

/* ── Trạng thái ứng dụng ─────────────────────────────────── */
typedef struct {
    /* Trang đăng nhập */
    GtkWidget    *window;
    GtkWidget    *stack;
    GtkWidget    *host_entry;
    GtkWidget    *port_entry;
    GtkWidget    *user_entry;
    GtkWidget    *pass_entry;
    GtkWidget    *connect_btn;
    GtkWidget    *signup_btn;
    GtkWidget    *login_status;
    GtkWidget    *login_spinner;

    /* Trang chat */
    GtkWidget    *header_bar;
    GtkWidget    *chat_view;
    GtkTextBuffer*chat_buf;
    GtkTextMark  *end_mark;
    GtkWidget    *msg_entry;
    GtkWidget    *send_btn;
    GtkWidget    *user_list;
    GtkWidget    *status_label;
    GtkWidget    *recipient_bar;
    GtkWidget    *recipient_label;

    /* Text tags */
    GtkTextTag   *tag_time;
    GtkTextTag   *tag_system;
    GtkTextTag   *tag_private;
    GtkTextTag   *tag_error;
    GtkTextTag   *tag_join;
    GtkTextTag   *tag_sender;
    GtkTextTag   *tag_self;

    /* Mạng */
    int           sock;
    char          username[MAX_USERNAME_LEN];
    char          recipient[MAX_USERNAME_LEN];
    uint8_t       session_key[AES_KEY_SIZE];
    crypto_ctx_t  crypto;
    volatile int  connected;
    pthread_t     rx_tid;
    guint         list_timer_id;
} App;

static App app;

/* ── Forward declarations ────────────────────────────────── */
typedef struct {
    char host[256];
    int  port;
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
} ConnectArgs;

typedef struct {
    int   type;
    char *text;
} UIMsgData;

static int send_command(uint8_t type, const void *payload, uint16_t plain_len);
static int recv_frame_gui(struct chat_frame *f);
static int frame_hmac(const struct chat_frame *f, uint8_t hmac_out[SHA256_DIGEST_SIZE]);
static void append_chat_text(const char *text, int msg_type);
static gboolean ui_on_message(gpointer data);
static gboolean ui_on_disconnect(gpointer data);
static gboolean ui_connect_ok(gpointer data);
static gboolean ui_connect_fail(gpointer data);

/* ── CSS theme ─────────────────────────────────────────────
 *
 * Chỉ dùng thuộc tính được GTK3 hỗ trợ. Các thuộc tính bị
 * loại bỏ so với phiên bản trước:
 *   - @import (không hỗ trợ)
 *   - text-transform (không hỗ trợ)
 *   - box-shadow (không hỗ trợ)
 *   - transition (không hỗ trợ)
 *   - letter-spacing (không hỗ trợ)
 *   - caret-color (không hỗ trợ)
 *   - linear-gradient trên button (không ổn định, dùng màu đơn)
 *
 * Bảng màu:
 *   Nền chính  : #1a1f2e  (xanh đen đậm)
 *   Nền card   : #242938  (xanh đen nhạt hơn)
 *   Nền input  : #2d3347  (xanh xám)
 *   Border     : #3d4466  (viền phân cách)
 *   Accent     : #4f8ef7  (xanh lam sáng)
 *   Text chính : #dde3f5  (trắng ngà)
 *   Text mờ    : #7a84a8  (xám xanh)
 * ──────────────────────────────────────────────────────────── */
static const char *APP_CSS =

    /* ===================================================================
     * Bảng màu:
     *   #0e1120  nền tối nhất (window, statusbar)
     *   #141829  nền tối (sidebar, headerbar, msg-box)
     *   #1c2236  nền card / pm-bar
     *   #242c42  nền input / button disabled
     *   #2e3855  viền / row hover
     *   #3d4e7a  viền focus / accent mờ
     *   #4f8ef7  accent xanh lam
     *   #dde3f5  chữ chính
     *   #7a86aa  chữ mờ
     * =================================================================== */

    /* === Cửa sổ chính === */
    "window { background-color: #0e1120; }\n"

    /* === HeaderBar ===
     * Adwaita dùng background-image để vẽ gradient/nền,
     * phải set background-image: none để override.          */
    "headerbar,\n"
    "headerbar:backdrop {\n"
    "  background-color: #141829;\n"
    "  background-image: none;\n"
    "  border-bottom: 1px solid #2e3855;\n"
    "  min-height: 50px;\n"
    "  padding: 0 10px;\n"
    "}\n"
    "headerbar .title {\n"
    "  color: #dde3f5;\n"
    "  font-weight: bold;\n"
    "  font-size: 14px;\n"
    "}\n"
    "headerbar .subtitle { color: #7a86aa; font-size: 11px; }\n"

    /* === Nút hệ thống (close/min/max) trên headerbar === */
    "headerbar button {\n"
    "  background-color: transparent;\n"
    "  background-image: none;\n"
    "  border: none;\n"
    "  color: #7a86aa;\n"
    "  min-height: 0;\n"
    "  min-width: 0;\n"
    "  padding: 6px;\n"
    "  border-radius: 4px;\n"
    "}\n"
    "headerbar button:hover {\n"
    "  background-color: #2e3855;\n"
    "  color: #dde3f5;\n"
    "}\n"

    /* === Card login === */
    ".login-card {\n"
    "  background-color: #1c2236;\n"
    "  border-radius: 14px;\n"
    "  border: 1px solid #2e3855;\n"
    "  padding: 36px;\n"
    "}\n"
    ".login-subtitle { color: #7a86aa; font-size: 13px; }\n"

    /* === Nhãn trường form === */
    ".field-label {\n"
    "  color: #9aa8c8;\n"
    "  font-size: 12px;\n"
    "  font-weight: bold;\n"
    "}\n"

    /* === Entry (ô nhập liệu) ===
     * Adwaita cũng override entry bằng background-image, phải clear. */
    "entry {\n"
    "  background-color: #242c42;\n"
    "  background-image: none;\n"
    "  color: #dde3f5;\n"
    "  border: 1px solid #3d4e7a;\n"
    "  border-radius: 8px;\n"
    "  padding: 8px 12px;\n"
    "  min-height: 22px;\n"
    "  font-size: 14px;\n"
    "}\n"
    "entry:focus {\n"
    "  background-color: #2a3352;\n"
    "  background-image: none;\n"
    "  border-color: #4f8ef7;\n"
    "}\n"
    "entry selection { background-color: #4f8ef7; color: #ffffff; }\n"

    /* === Nút Connect ===
     * Adwaita render button bằng background-image (gradient).
     * background-image: none + background-color mới override được. */
    ".connect-btn,\n"
    ".connect-btn:link {\n"
    "  background-color: #4f8ef7;\n"
    "  background-image: none;\n"
    "  color: #ffffff;\n"
    "  border-radius: 8px;\n"
    "  font-weight: bold;\n"
    "  font-size: 14px;\n"
    "  min-height: 42px;\n"
    "  border: none;\n"
    "  padding: 0 20px;\n"
    "  outline: none;\n"
    "}\n"
    ".connect-btn:hover {\n"
    "  background-color: #3a7ae8;\n"
    "  background-image: none;\n"
    "}\n"
    ".connect-btn:active {\n"
    "  background-color: #2866d4;\n"
    "  background-image: none;\n"
    "}\n"
    ".connect-btn:disabled {\n"
    "  background-color: #242c42;\n"
    "  background-image: none;\n"
    "  color: #4a5570;\n"
    "}\n"

    /* === Nút Signup === */
    ".signup-btn {\n"
    "  background-color: transparent;\n"
    "  border: 1px solid #4f8ef7;\n"
    "  color: #4f8ef7;\n"
    "  border-radius: 8px;\n"
    "  font-weight: bold;\n"
    "  font-size: 14px;\n"
    "  min-height: 42px;\n"
    "  padding: 0 20px;\n"
    "}\n"
    ".signup-btn:hover {\n"
    "  background-color: rgba(79, 142, 247, 0.1);\n"
    "}\n"

    /* === Sidebar === */
    ".sidebar {\n"
    "  background-color: #141829;\n"
    "  border-right: 1px solid #2e3855;\n"
    "}\n"
    ".sidebar-title {\n"
    "  color: #4e5a7a;\n"
    "  font-size: 11px;\n"
    "  font-weight: bold;\n"
    "  padding: 16px 14px 8px 14px;\n"
    "}\n"

    /* listbox */
    "list {\n"
    "  background-color: transparent;\n"
    "  background-image: none;\n"
    "  color: #9aa8c8;\n"
    "}\n"
    "list row {\n"
    "  background-color: transparent;\n"
    "  background-image: none;\n"
    "  border-radius: 6px;\n"
    "  margin: 1px 6px;\n"
    "}\n"
    "list row:hover { background-color: #1e2740; }\n"
    "list row:selected {\n"
    "  background-color: #253060;\n"
    "  background-image: none;\n"
    "}\n"
    ".user-row { color: #9aa8c8; font-size: 13px; padding: 7px 10px; }\n"

    /* === Vùng chat === */
    "textview { font-size: 14px; font-family: monospace; }\n"
    "textview text {\n"
    "  background-color: #0e1120;\n"
    "  color: #dde3f5;\n"
    "}\n"

    /* === Khu nhập tin nhắn === */
    ".msg-box {\n"
    "  background-color: #141829;\n"
    "  border-top: 1px solid #2e3855;\n"
    "  padding: 10px 12px;\n"
    "}\n"
    ".msg-entry {\n"
    "  background-color: #242c42;\n"
    "  background-image: none;\n"
    "  color: #dde3f5;\n"
    "  border-radius: 8px;\n"
    "  border: 1px solid #3d4e7a;\n"
    "  padding: 8px 14px;\n"
    "  min-height: 22px;\n"
    "  font-size: 14px;\n"
    "}\n"
    ".msg-entry:focus {\n"
    "  background-color: #2a3352;\n"
    "  background-image: none;\n"
    "  border-color: #4f8ef7;\n"
    "}\n"

    /* === Nút Send === */
    ".send-btn {\n"
    "  background-color: #4f8ef7;\n"
    "  background-image: none;\n"
    "  color: #ffffff;\n"
    "  border-radius: 8px;\n"
    "  border: none;\n"
    "  font-weight: bold;\n"
    "  font-size: 13px;\n"
    "  padding: 8px 20px;\n"
    "  min-height: 0;\n"
    "  outline: none;\n"
    "}\n"
    ".send-btn:hover {\n"
    "  background-color: #3a7ae8;\n"
    "  background-image: none;\n"
    "}\n"
    ".send-btn:active {\n"
    "  background-color: #2866d4;\n"
    "  background-image: none;\n"
    "}\n"
    ".send-btn:disabled {\n"
    "  background-color: #242c42;\n"
    "  background-image: none;\n"
    "  color: #4a5570;\n"
    "}\n"

    /* === Thanh trạng thái === */
    ".statusbar {\n"
    "  background-color: #0a0e1a;\n"
    "  color: #4e5a7a;\n"
    "  padding: 5px 14px;\n"
    "  font-size: 12px;\n"
    "  border-top: 1px solid #2e3855;\n"
    "}\n"

    /* === Thanh PM (private message) === */
    ".pm-bar {\n"
    "  background-color: #1a2240;\n"
    "  border-bottom: 1px solid #3d4e7a;\n"
    "  padding: 7px 12px;\n"
    "}\n"
    /* Label bên trong pm-bar: dùng selector trực tiếp */
    ".pm-bar label {\n"
    "  color: #6fa3f7;\n"
    "  font-size: 12px;\n"
    "  font-weight: bold;\n"
    "}\n"
    /* Nút Cancel trong PM bar */
    ".pm-bar button {\n"
    "  background-color: #2e3855;\n"
    "  background-image: none;\n"
    "  color: #9aa8c8;\n"
    "  border: 1px solid #3d4e7a;\n"
    "  border-radius: 6px;\n"
    "  font-size: 11px;\n"
    "  padding: 3px 10px;\n"
    "  min-height: 0;\n"
    "}\n"
    ".pm-bar button:hover {\n"
    "  background-color: #3d4e7a;\n"
    "  background-image: none;\n"
    "  color: #dde3f5;\n"
    "}\n"

    /* === Nhãn lỗi === */
    ".error-status { color: #f47067; }\n"

    /* === Dải phân cách === */
    "separator { background-color: #2e3855; min-height: 1px; min-width: 1px; }\n"
;


/* ═══════════════════════════════════════════════════════════
 * Các hàm hỗ trợ Mạng / Mã hóa (cùng giao thức với terminal client)
 * ═══════════════════════════════════════════════════════════ */


// TIER 1: defines real-time behavior
// These control connection, receiving loop, and sending


/**
 * connect_to_server - Tạo socket TCP và kết nối tới host:port.
 *
 * @host: Hostname hoặc địa chỉ IP của server.
 * @port: Cổng TCP cần kết nối.
 *
 * Tác dụng phụ:
 * - Gán file descriptor vào app.sock (hoặc -1 khi thất bại).
 *
 * Giá trị trả về:
 * - 0 khi kết nối thành công.
 * - -1 nếu socket/resolve/connect thất bại.
 */

 // 1.1. socket connection to the server
 // - open socket
 // - calls socket(), connect()
 // - defines when connections starts
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



/**
 * recv_thread_func - Luồng nền nhận dữ liệu từ server và đẩy cập nhật sang UI.
 *
 * @data: Không sử dụng.
 *
 * Hành vi:
 * - Gửi yêu cầu danh sách người dùng (MSG_TYPE_LIST) ngay khi bắt đầu.
 * - Lặp nhận frame:
 *   + recv_frame_gui + giải mã bằng AES session key.
 *   + Phân loại message thành một trong UI_MSG_NORMAL/SYSTEM/PRIVATE/USERLIST.
 *   + Tạo UIMsgData và gọi g_idle_add(ui_on_message, d).
 * - Nếu mất kết nối: gọi g_idle_add(ui_on_disconnect, NULL).
 * - Nếu system message chứa "joined"/"left": tự động yêu cầu lại danh sách.
 *
 * Giá trị trả về: NULL (thread kết thúc).
 */
 // 1.2. real-time engine
 // - infinite loop
 // - decrypt
 // - dispatch message
 // - keep connection alive
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
        if (strncmp(text, "***", 3) == 0)
            msg_type = UI_MSG_SYSTEM;
        else if (strncmp(text, "Online users:", 13) == 0)
            msg_type = UI_MSG_USERLIST;
        else if (strstr(text, "(private)") != NULL)
            msg_type = UI_MSG_PRIVATE;

        UIMsgData *d = g_new(UIMsgData, 1);
        d->type = msg_type;
        d->text = g_strdup(text);
        g_idle_add(ui_on_message, d);

        if (msg_type == UI_MSG_SYSTEM &&
            (strstr(text, "joined") || strstr(text, "left")))
            send_command(MSG_TYPE_LIST, "", 0);
    }
    return NULL;
}





/**
 * send_chat - Đóng gói chat message (chat_payload) và gửi lên server.
 *
 * @recipient: Người nhận; nếu chuỗi rỗng ("") thì server sẽ xử lý
 *             theo logic broadcast hoặc private.
 * @message:   Nội dung tin nhắn cần gửi.
 *
 * Giá trị trả về:
 * - 0 khi gửi thành công.
 * - -1 nếu send_command thất bại.
 */

// 1.3. send chat
// - build chat payload
// - calls send_command()
// - sends message to server
static int send_chat(const char *recipient, const char *message)
{
    struct chat_payload cp;
    memset(&cp, 0, sizeof(cp));
    snprintf(cp.sender, sizeof(cp.sender), "%s", app.username);
    snprintf(cp.recipient, sizeof(cp.recipient), "%s", recipient);
    snprintf(cp.message, sizeof(cp.message), "%s", message);
    cp.timestamp = (uint64_t)time(NULL);
    return send_command(MSG_TYPE_CHAT, &cp, sizeof(cp));
}



















// TIER 2: Protocol / transport layer logic
// These define how data flows over the socket



// 2.1
// - encrypt payload
// - build frame
// - calls send() 
// -> actual network transmissions
/**
 * send_command - Mã hóa payload bằng AES-256-CBC (session key) và gửi một frame.
 *
 * @type:       Loại message/frame (MSG_TYPE_*).
 * @payload:    Plaintext payload cần gửi.
 * @plain_len:  Độ dài plaintext payload (byte).
 *
 * Hành vi:
 * - Tạo IV ngẫu nhiên.
 * - AES-encrypt payload → f.payload, cập nhật f.payload_len.
 * - Tính digest toàn vẹn của frame → f.hmac.
 * - Gửi: header (không bao gồm phần payload tĩnh) + payload ciphertext.
 *
 * Giá trị trả về:
 * - 0 khi gửi thành công.
 * - -1 nếu mã hóa/ioctl hoặc send thất bại.
 */
static int send_command(uint8_t type, const void *payload, uint16_t plain_len)
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







// 2.2
// - call recv()
// - reads frame header
// - reads payload
// - verifies integrity
// -> actual network receiving
/**
 * recv_frame_gui - Nhận frame từ server và kiểm tra tính toàn vẹn (digest).
 *
 * @f: Buffer frame sẽ được ghi vào (header + payload nếu có).
 *
 * Kiểm tra:
 * - f->version == PROTO_VERSION.
 * - f->payload_len <= MAX_DATA_SIZE.
 * - f->hmac khớp với digest tính lại từ frame.
 *
 * Giá trị trả về:
 * - 0 khi nhận đủ và digest hợp lệ.
 * - -1 nếu recv thất bại, dữ liệu không hợp lệ, hoặc digest không khớp.
 */
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















// Tier 3 — Session / authentication logic
// These define connection lifecycle


// 3.1 do_auth()
// - login handshake
// - key derivation
// - session setup
/**
 * do_auth - Bắt tay xác thực với server để thiết lập session AES key.
 *
 * @username: Tên đăng nhập của người dùng.
 * @password: Mật khẩu dạng chuỗi (được hash trong kernel driver).
 *
 * Quy trình trong hàm:
 * - SHA-256 password qua driver → ap.password_hash.
 * - Gửi frame auth được mã hóa bằng bootstrap key (all-zero).
 * - Nhận response, giải mã bằng bootstrap key.
 * - Nếu OK: lấy session salt (16 byte) từ response → derive app.session_key.
 *
 * Tác dụng phụ:
 * - Cập nhật app.session_key và app.username.
 *
 * Giá trị trả về:
 * - 0 khi xác thực thành công.
 * - -1 khi xác thực thất bại hoặc bất kỳ bước nào lỗi.
 */
 
// check auth
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

    snprintf(app.username, sizeof(app.username), "%s", username);
    return 0;
}






// 3.2. connect_thread_func();
// - opens crypto driver
// - call connect_to_server()
// - do auth()
// - start recv_thread_func()
// -> connection startup pipline

/**
 * connect_thread_func - Thread nền thực hiện mở driver + kết nối + do_auth.
 *
 * @data: Con trỏ ConnectArgs (được cấp phát trong handler GUI; sẽ được giải phóng trong hàm).
 *
 * Quy trình:
 * - Gọi crypto_open(&app.crypto).
 * - Gọi connect_to_server(host, port).
 * - Gọi do_auth(username, password) → thiết lập app.session_key.
 * - Đặt app.connected = 1 và pthread_create(recv_thread_func).
 * - Thông báo kết quả qua g_idle_add(ui_connect_ok / ui_connect_fail).
 *
 * Giá trị trả về: NULL.
 */
static void *connect_thread_func(void *data)
{
    ConnectArgs *args = data;

    if (crypto_open(&app.crypto) < 0) {
        g_idle_add(ui_connect_fail,
                   g_strdup("Cannot open /dev/crypto_chat \342\200\224 "
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
                   g_strdup("Authentication failed \342\200\224 "
                            "wrong credentials?"));
        g_free(args);
        return NULL;
    }

    app.connected = 1;
    pthread_create(&app.rx_tid, NULL, recv_thread_func, NULL);

    char *host_info = g_strdup_printf("%s:%d", args->host, args->port);
    g_idle_add(ui_connect_ok, host_info);

    g_free(args);
    return NULL;
}





// 3.3 Register logic

static void *signup_thread_func(void *data)
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
    crypto_sha256(&app.crypto, (uint8_t *)args->password, strlen(args->password), ap.password_hash);

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
        g_idle_add(ui_connect_fail, g_strdup("Sign up successful! Please connect."));
    } else {
        /* Decode error message if any */
        uint32_t plen = 0;
        uint8_t plain[MAX_DATA_SIZE];
        crypto_aes_decrypt(&app.crypto, zero_key, f.iv, f.payload, f.payload_len, plain, &plen);
        plain[plen] = '\0';
        g_idle_add(ui_connect_fail, g_strdup_printf("Sign up failed: %s", (char*)plain));
    }

    close(app.sock);
    crypto_close(&app.crypto);
    g_free(args);
    return NULL;
}

static void on_signup_clicked(GtkWidget *w, gpointer data)
{
    (void)w; (void)data;
    const char *host     = gtk_entry_get_text(GTK_ENTRY(app.host_entry));
    const char *port_str = gtk_entry_get_text(GTK_ENTRY(app.port_entry));
    const char *user     = gtk_entry_get_text(GTK_ENTRY(app.user_entry));
    const char *pass     = gtk_entry_get_text(GTK_ENTRY(app.pass_entry));

    if (!user[0] || !pass[0]) {
        gtk_label_set_text(GTK_LABEL(app.login_status), "Username and password required");
        return;
    }

    gtk_widget_set_sensitive(app.connect_btn, FALSE);
    gtk_widget_set_sensitive(app.signup_btn, FALSE);
    gtk_spinner_start(GTK_SPINNER(app.login_spinner));
    gtk_label_set_text(GTK_LABEL(app.login_status), "Signing up...");

    ConnectArgs *args = g_new0(ConnectArgs, 1);
    snprintf(args->host, sizeof(args->host), "%s", host[0] ? host : DEFAULT_HOST);
    args->port = port_str[0] ? atoi(port_str) : 9090;
    snprintf(args->username, sizeof(args->username), "%s", user);
    snprintf(args->password, sizeof(args->password), "%s", pass);

    pthread_t tid;
    pthread_create(&tid, NULL, signup_thread_func, args);
    pthread_detach(tid);
}











// Tier 4 — App behavior logic
// These affect how messages behave


// 4.1 on_send_clicked()
// - parses /list
// - parses /quit
// parses /msg
// calls send_chat()
// -> user command logic


/**
 * on_send_clicked - Handler khi nhấn nút "Send".
 *
 * @w:    Widget được nhấn (không dùng).
 * @data: User data (không dùng).
 *
 * Hành vi:
 * - Nếu không connected → return ngay.
 * - Lấy text từ msg_entry.
 * - Xử lý các lệnh đặc biệt:
 *   + "/list"          → gửi MSG_TYPE_LIST.
 *   + "/quit"          → gửi MSG_TYPE_LOGOUT, đặt connected = 0, vô hiệu hóa input.
 *   + "/msg user text" → gửi tin nhắn private đến người dùng chỉ định.
 *   + Văn bản khác     → broadcast (recipient = "").
 * - Sau khi gửi: xóa msg_entry và focus trở lại ô nhập.
 *
 * Giá trị trả về: void.
 */
static void on_send_clicked(GtkWidget *w, gpointer data)
{
    (void)w; (void)data;
    if (!app.connected) return;

    const char *text = gtk_entry_get_text(GTK_ENTRY(app.msg_entry));
    if (!text[0]) return;

    if (strncmp(text, "/list", 5) == 0) {
        send_command(MSG_TYPE_LIST, "", 0);
    } else if (strncmp(text, "/quit", 5) == 0) {
        send_command(MSG_TYPE_LOGOUT, "bye", 3);
        app.connected = 0;
        append_chat_text("Disconnected by user.", UI_MSG_SYSTEM);
        gtk_widget_set_sensitive(app.msg_entry, FALSE);
        gtk_widget_set_sensitive(app.send_btn, FALSE);
    } else if (strncmp(text, "/msg ", 5) == 0) {
        const char *rest = text + 5;
        const char *sp = strchr(rest, ' ');
        if (sp) {
            char target[MAX_USERNAME_LEN] = {0};
            int name_len = (int)(sp - rest);
            if (name_len >= MAX_USERNAME_LEN) name_len = MAX_USERNAME_LEN - 1;
            memcpy(target, rest, name_len);
            send_chat(target, sp + 1);
        }
    } else {
        send_chat(app.recipient, text);
    }

    gtk_entry_set_text(GTK_ENTRY(app.msg_entry), "");
    gtk_widget_grab_focus(app.msg_entry);
}














// Tier 5 — Supporting core logic (encryption logic)

// 5.1 frame_hmac
// -> integrity hash
/**
 * frame_hmac - Tính giá trị toàn vẹn/digest (dùng SHA-256) cho một `chat_frame`.
 *
 * Code GUI này dùng `crypto_sha256` (không phải HMAC) với bố cục dữ liệu đầu vào:
 *   type (1) || payload_len (2) || iv (AES_IV_SIZE) || payload
 *
 * @f:         Frame cần tính.
 * @hmac_out:  Buffer nhận kết quả, đủ SHA256_DIGEST_SIZE byte.
 *
 * Giá trị trả về:
 * - 0 khi thành công.
 * - -1 khi gặp lỗi (ví dụ malloc hoặc sha256 thất bại).
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
    buf[2] =  f->payload_len       & 0xFF;
    memcpy(buf + 3,              f->iv,      AES_IV_SIZE);
    memcpy(buf + 3 + AES_IV_SIZE, f->payload, f->payload_len);

    ret = crypto_sha256(&app.crypto, buf, (uint32_t)buf_len, hmac_out);
    free(buf);
    return ret;
}


// crypto_aes_encrypt, crypto_aes_decrypt, crypto_sha256












/* ═══════════════════════════════════════════════════════════
 * Khởi tạo Text Tag
 * ═══════════════════════════════════════════════════════════ */

/**
 * setup_text_tags - Tạo các GtkTextTag để định dạng màu sắc cho từng loại tin nhắn.
 *
 * Giá trị trả về: void.
 */
static void setup_text_tags(void)
{
    app.tag_time = gtk_text_buffer_create_tag(app.chat_buf, "time",
        "foreground", "#4a5580", "scale", 0.9, NULL);
    app.tag_system = gtk_text_buffer_create_tag(app.chat_buf, "system",
        "foreground", "#e8a742", "style", PANGO_STYLE_ITALIC, NULL);
    app.tag_private = gtk_text_buffer_create_tag(app.chat_buf, "private",
        "foreground", "#6fa3f7", "weight", PANGO_WEIGHT_BOLD, NULL);
    app.tag_error = gtk_text_buffer_create_tag(app.chat_buf, "error",
        "foreground", "#f47067", "weight", PANGO_WEIGHT_BOLD, NULL);
    app.tag_join = gtk_text_buffer_create_tag(app.chat_buf, "join",
        "foreground", "#4ec97e", "style", PANGO_STYLE_ITALIC, NULL);
    app.tag_sender = gtk_text_buffer_create_tag(app.chat_buf, "sender",
        "foreground", "#6fa3f7", "weight", PANGO_WEIGHT_BOLD, NULL);
    app.tag_self = gtk_text_buffer_create_tag(app.chat_buf, "self",
        "foreground", "#4ec97e", NULL);
}

/* ═══════════════════════════════════════════════════════════
 * Hàm cập nhật UI (luôn gọi trên GTK main thread)
 * ═══════════════════════════════════════════════════════════ */

/**
 * append_chat_text - Chèn một dòng văn bản vào chat buffer với style tương ứng.
 *
 * @text:     Chuỗi sẽ hiển thị (thường đã gồm prefix/phân loại).
 * @msg_type: UI_MSG_* để chọn tag style hoặc hướng parse.
 *
 * Hành vi:
 * - Insert vào app.chat_buf với GtkTextTag phù hợp.
 * - Cuộn đến vị trí cuối (end_mark).
 *
 * Ghi chú: Default case có parser cho định dạng "[HH:MM:SS] sender: message"
 * để tách thời gian, tên người gửi và nội dung tin nhắn.
 *
 * Giá trị trả về: void.
 */
static void append_chat_text(const char *text, int msg_type)
{
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(app.chat_buf, &end);

    switch (msg_type) {
    case UI_MSG_ERROR:
        gtk_text_buffer_insert_with_tags(app.chat_buf, &end, text, -1,
                                         app.tag_error, NULL);
        break;

    case UI_MSG_SYSTEM:
        gtk_text_buffer_insert_with_tags(app.chat_buf, &end, text, -1,
            strstr(text, "joined") ? app.tag_join : app.tag_system, NULL);
        break;

    case UI_MSG_PRIVATE:
        gtk_text_buffer_insert_with_tags(app.chat_buf, &end, text, -1,
                                         app.tag_private, NULL);
        break;

    default:
        /* Parse "[HH:MM:SS] sender: message" để định dạng màu sắc phong phú */
        if (text[0] == '[') {
            const char *rb = strchr(text, ']');
            if (rb) {
                int ts_len = (int)(rb - text + 1);
                gtk_text_buffer_insert_with_tags(app.chat_buf, &end,
                    text, ts_len, app.tag_time, NULL);
                gtk_text_buffer_insert(app.chat_buf, &end, " ", 1);

                const char *rest = rb + 1;
                while (*rest == ' ') rest++;

                const char *colon = strstr(rest, ": ");
                if (colon) {
                    int name_len = (int)(colon - rest);
                    gtk_text_buffer_insert_with_tags(app.chat_buf, &end,
                        rest, name_len, app.tag_sender, NULL);
                    gtk_text_buffer_insert(app.chat_buf, &end, colon, -1);
                } else {
                    gtk_text_buffer_insert(app.chat_buf, &end, rest, -1);
                }
                break;
            }
        }
        gtk_text_buffer_insert(app.chat_buf, &end, text, -1);
        break;
    }

    gtk_text_buffer_insert(app.chat_buf, &end, "\n", 1);
    gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(app.chat_view),
                                 app.end_mark, 0.0, FALSE, 0, 0);
}

/**
 * update_user_list - Cập nhật danh sách người dùng trực tuyến (sidebar) và status_label.
 *
 * @text: Chuỗi server trả về (ví dụ: "Online users: alice, bob, ...").
 *
 * Hành vi:
 * - Xóa các widget cũ trong app.user_list.
 * - Tách danh sách theo dấu ',' và trim whitespace.
 * - Nếu tên giống app.username thì hiển thị "(you)".
 * - Cập nhật status_label theo số người dùng online + thông tin AES.
 *
 * Giá trị trả về: void.
 */
static void update_user_list(const char *text)
{
    GList *children = gtk_container_get_children(GTK_CONTAINER(app.user_list));
    for (GList *l = children; l; l = l->next)
        gtk_widget_destroy(l->data);
    g_list_free(children);

    const char *start = strstr(text, ": ");
    if (!start) return;
    start += 2;

    char *copy = g_strdup(start);
    char *saveptr = NULL;
    char *token = strtok_r(copy, ",", &saveptr);
    int count = 0;

    while (token) {
        while (*token == ' ') token++;
        char *tail = token + strlen(token) - 1;
        while (tail > token && *tail == ' ') *tail-- = '\0';

        if (!*token) { token = strtok_r(NULL, ",", &saveptr); continue; }

        char buf[128];
        gboolean is_self = (strcmp(token, app.username) == 0);
        if (is_self)
            snprintf(buf, sizeof(buf), "  \342\227\217  %s  (you)", token);
        else
            snprintf(buf, sizeof(buf), "  \342\227\217  %s", token);

        GtkWidget *lbl = gtk_label_new(buf);
        gtk_widget_set_halign(lbl, GTK_ALIGN_START);
        gtk_style_context_add_class(gtk_widget_get_style_context(lbl),
                                    is_self ? "user-row user-row-self" : "user-row");
        g_object_set_data_full(G_OBJECT(lbl), "uname",
                               g_strdup(token), g_free);

        gtk_list_box_insert(GTK_LIST_BOX(app.user_list), lbl, -1);
        gtk_widget_show_all(lbl);
        count++;
        token = strtok_r(NULL, ",", &saveptr);
    }
    g_free(copy);

    char status[256];
    snprintf(status, sizeof(status),
             "  \360\237\224\220 AES-256-CBC  \342\200\224  \342\232\241 Connected  \342\200\224  %d user%s online",
             count, count == 1 ? "" : "s");
    gtk_label_set_text(GTK_LABEL(app.status_label), status);
}

/* ═══════════════════════════════════════════════════════════
 * Idle callbacks an toàn cho thread (đẩy từ receiver thread)
 * ═══════════════════════════════════════════════════════════ */

/**
 * ui_on_message - Idle callback để cập nhật UI khi receiver thread "đẩy" message.
 *
 * @data: Con trỏ UIMsgData gồm:
 *   - type: UI_MSG_*
 *   - text: Chuỗi message (đã được copy riêng)
 *
 * Hành vi:
 * - Nếu type == UI_MSG_USERLIST: gọi update_user_list.
 * - Ngược lại: gọi append_chat_text.
 * - Giải phóng bộ nhớ UIMsgData sau khi xử lý.
 *
 * Giá trị trả về: G_SOURCE_REMOVE.
 */
static gboolean ui_on_message(gpointer data)
{
    UIMsgData *d = data;

    if (d->type == UI_MSG_USERLIST) {
        update_user_list(d->text);
    } else {
        append_chat_text(d->text, d->type);
    }

    g_free(d->text);
    g_free(d);
    return G_SOURCE_REMOVE;
}

/**
 * ui_on_disconnect - Idle callback khi mất kết nối với server.
 *
 * Hành vi:
 * - Hiển thị thông báo "[!] Connection lost" trong cửa sổ chat.
 * - Vô hiệu hóa msg_entry và send_btn.
 * - Cập nhật status_label thông báo đã ngắt kết nối.
 *
 * Giá trị trả về: G_SOURCE_REMOVE.
 */
static gboolean ui_on_disconnect(gpointer data)
{
    (void)data;
    append_chat_text("[!] Connection lost", UI_MSG_ERROR);
    gtk_widget_set_sensitive(app.msg_entry, FALSE);
    gtk_widget_set_sensitive(app.send_btn, FALSE);
    gtk_label_set_text(GTK_LABEL(app.status_label),
                       "  Disconnected — restart to reconnect");
    return G_SOURCE_REMOVE;
}



/* ═══════════════════════════════════════════════════════════
 * Connect Thread (thực hiện xác thực ở background)
 * ═══════════════════════════════════════════════════════════ */

/**
 * ui_connect_ok - Callback trên GTK main loop khi kết nối/xác thực thành công.
 *
 * @data: Chuỗi "host:port" cấp phát động (được giải phóng trong hàm).
 *
 * Hành vi:
 * - Chuyển stack sang trang "chat".
 * - Cập nhật header bar title/subtitle.
 * - Kích hoạt msg_entry/send_btn và đặt focus vào msg_entry.
 * - In system message thông báo đã kết nối thành công.
 *
 * Giá trị trả về: G_SOURCE_REMOVE.
 */
static gboolean ui_connect_ok(gpointer data)
{
    char *host_info = data;

    gtk_stack_set_visible_child_name(GTK_STACK(app.stack), "chat");

    char title[256];
    snprintf(title, sizeof(title), "CryptoChat \342\200\224 %s@%s",
             app.username, host_info);
    gtk_header_bar_set_title(GTK_HEADER_BAR(app.header_bar), title);
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(app.header_bar),
                                "AES-256-CBC + SHA-256 Encrypted");

    gtk_widget_set_sensitive(app.msg_entry, TRUE);
    gtk_widget_set_sensitive(app.send_btn, TRUE);
    gtk_widget_grab_focus(app.msg_entry);

    append_chat_text("Connected. All messages are encrypted with AES-256-CBC.",
                     UI_MSG_SYSTEM);

    g_free(host_info);
    return G_SOURCE_REMOVE;
}

/**
 * ui_connect_fail - Callback trên GTK main loop khi kết nối/xác thực thất bại.
 *
 * @data: Chuỗi thông điệp lỗi (được giải phóng trong hàm).
 *
 * Hành vi:
 * - Hiển thị thông điệp lỗi lên login_status và thêm class "error-status".
 * - Kích hoạt lại connect_btn và dừng login_spinner.
 *
 * Giá trị trả về: G_SOURCE_REMOVE.
 */
static gboolean ui_connect_fail(gpointer data)
{
    char *msg = data;
    gtk_label_set_text(GTK_LABEL(app.login_status), msg);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.login_status), "error-status");

    gtk_widget_set_sensitive(app.connect_btn, TRUE);
    gtk_widget_set_sensitive(app.signup_btn, TRUE);
    gtk_spinner_stop(GTK_SPINNER(app.login_spinner));

    g_free(msg);
    return G_SOURCE_REMOVE;
}


/* ═══════════════════════════════════════════════════════════
 * Các GTK Signal Handler
 * ═══════════════════════════════════════════════════════════ */

/**
 * on_connect_clicked - Handler khi nhấn nút "Connect".
 *
 * @w:    Widget được nhấn (không dùng trong hàm).
 * @data: User data (không dùng trong hàm).
 *
 * Hành vi:
 * - Đọc dữ liệu từ entry: host, port, username, password.
 * - Kiểm tra bắt buộc: phải có username và password.
 * - Sau đó khởi tạo thread nền connect_thread_func để mở driver + kết nối + xác thực.
 *
 * Giá trị trả về: void.
 */
static void on_connect_clicked(GtkWidget *w, gpointer data)
{
    (void)w; (void)data;
    const char *host     = gtk_entry_get_text(GTK_ENTRY(app.host_entry));
    const char *port_str = gtk_entry_get_text(GTK_ENTRY(app.port_entry));
    const char *user     = gtk_entry_get_text(GTK_ENTRY(app.user_entry));
    const char *pass     = gtk_entry_get_text(GTK_ENTRY(app.pass_entry));

    if (!user[0] || !pass[0]) {
        gtk_label_set_text(GTK_LABEL(app.login_status),
                           "Username and password are required");
        gtk_style_context_add_class(
            gtk_widget_get_style_context(app.login_status), "error-status");
        return;
    }

    gtk_style_context_remove_class(
        gtk_widget_get_style_context(app.login_status), "error-status");
    gtk_widget_set_sensitive(app.connect_btn, FALSE);
    gtk_spinner_start(GTK_SPINNER(app.login_spinner));
    gtk_label_set_text(GTK_LABEL(app.login_status), "Connecting...");

    ConnectArgs *args = g_new0(ConnectArgs, 1);
    snprintf(args->host, sizeof(args->host), "%s",
             host[0] ? host : DEFAULT_HOST);
    args->port = port_str[0] ? atoi(port_str) : 9090;
    snprintf(args->username, sizeof(args->username), "%s", user);
    snprintf(args->password, sizeof(args->password), "%s", pass);

    pthread_t tid;
    pthread_create(&tid, NULL, connect_thread_func, args);
    pthread_detach(tid);
}



/**
 * on_msg_activate - Handler khi nhấn Enter trong ô nhập liệu msg_entry.
 *
 * Thực tế gọi trực tiếp on_send_clicked để dùng chung logic gửi tin.
 *
 * @w:    Widget (không dùng).
 * @data: User data (không dùng).
 *
 * Giá trị trả về: void.
 */
static void on_msg_activate(GtkWidget *w, gpointer data)
{
    (void)w; (void)data;
    on_send_clicked(NULL, NULL);
}

/**
 * on_user_activated - Callback khi người dùng nhấn/activate một hàng trong user_list.
 *
 * @lb:   List box (không dùng).
 * @row:  Hàng được activate.
 * @data: User data (không dùng).
 *
 * Hành vi:
 * - Lấy "uname" từ data của widget con trong hàng được chọn.
 * - Nếu chọn chính mình (app.username) hoặc recipient hiện tại → hủy chế độ PM:
 *   xóa app.recipient và ẩn recipient_bar.
 * - Nếu chọn người khác → đặt app.recipient và hiển thị PM bar.
 *
 * Giá trị trả về: void.
 */
static void on_user_activated(GtkListBox *lb, GtkListBoxRow *row,
                              gpointer data)
{
    (void)lb; (void)data;
    if (!row) return;

    GtkWidget  *child = gtk_bin_get_child(GTK_BIN(row));
    const char *name  = g_object_get_data(G_OBJECT(child), "uname");
    if (!name) return;

    if (strcmp(name, app.username) == 0 ||
        strcmp(name, app.recipient) == 0) {
        memset(app.recipient, 0, sizeof(app.recipient));
        gtk_widget_hide(app.recipient_bar);
        return;
    }

    snprintf(app.recipient, sizeof(app.recipient), "%s", name);
    char *msg = g_strdup_printf(
        "<span foreground='#6fa3f7' weight='bold' size='small'>"
        "\342\234\211  Nhắn riêng tới: %s"
        "</span>"
        "<span foreground='#4a5a80' size='small'>"
        "  (nhấp lại để huỷ)"
        "</span>",
        name);
    gtk_label_set_markup(GTK_LABEL(app.recipient_label), msg);
    gtk_widget_show(app.recipient_bar);
    g_free(msg);
}

/**
 * on_clear_pm - Handler khi nhấn nút "Cancel" ở thanh PM.
 *
 * @w:    Widget (không dùng).
 * @data: User data (không dùng).
 *
 * Hành vi:
 * - Xóa app.recipient.
 * - Ẩn recipient_bar (tắt chế độ private message).
 *
 * Giá trị trả về: void.
 */
static void on_clear_pm(GtkWidget *w, gpointer data)
{
    (void)w; (void)data;
    memset(app.recipient, 0, sizeof(app.recipient));
    gtk_widget_hide(app.recipient_bar);
}

/**
 * on_list_timer - Callback timer định kỳ (mỗi LIST_INTERVAL_SEC giây).
 *
 * @data: Không sử dụng.
 *
 * Hành vi:
 * - Nếu app.connected đang hoạt động: gửi MSG_TYPE_LIST để làm mới danh sách online.
 *
 * Giá trị trả về: G_SOURCE_CONTINUE để tiếp tục lên lịch chu kỳ tiếp theo.
 */
static gboolean on_list_timer(gpointer data)
{
    (void)data;
    if (app.connected)
        send_command(MSG_TYPE_LIST, "", 0);
    return G_SOURCE_CONTINUE;
}

/**
 * on_window_destroy - Handler khi cửa sổ GUI bị đóng.
 *
 * @w:    Widget chính (không dùng).
 * @data: User data (không dùng).
 *
 * Hành vi:
 * - Gỡ timer làm mới danh sách nếu đang chạy.
 * - Nếu đang kết nối: gửi MSG_TYPE_LOGOUT trước khi thoát.
 * - Shutdown và đóng socket.
 * - Gọi crypto_close(&app.crypto) để giải phóng tài nguyên driver.
 * - Gọi gtk_main_quit() để thoát vòng lặp sự kiện GTK.
 *
 * Giá trị trả về: void.
 */
static void on_window_destroy(GtkWidget *w, gpointer data)
{
    (void)w; (void)data;

    if (app.list_timer_id > 0) {
        g_source_remove(app.list_timer_id);
        app.list_timer_id = 0;
    }

    if (app.connected) {
        app.connected = 0;
        send_command(MSG_TYPE_LOGOUT, "bye", 3);
    }

    if (app.sock >= 0) {
        shutdown(app.sock, SHUT_RDWR);
        close(app.sock);
        app.sock = -1;
    }

    crypto_close(&app.crypto);
    gtk_main_quit();
}

/* ═══════════════════════════════════════════════════════════
 * Xây dựng trang đăng nhập
 * ═══════════════════════════════════════════════════════════ */

/**
 * build_login_page - Tạo widget giao diện cho màn hình đăng nhập.
 *
 * Hàm dùng GTK để:
 * - Tạo các entry: host, port, username, password.
 * - Tạo nút "Connect", label trạng thái và spinner loading.
 * - Gắn signal "activate" cho entry và "clicked" cho nút vào on_connect_clicked.
 *
 * Giá trị trả về:
 * - GtkWidget* gốc của màn hình đăng nhập (outer container).
 */
static GtkWidget *build_login_page(void)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_halign(outer, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(outer, GTK_ALIGN_CENTER);

    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 18);
    gtk_style_context_add_class(gtk_widget_get_style_context(card),
                                "login-card");
    gtk_widget_set_size_request(card, 440, -1);
    gtk_container_set_border_width(GTK_CONTAINER(card), 40);

    /* Tiêu đề */
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title),
        "<span size='xx-large' weight='bold' foreground='#dde3f5'>"
        "\360\237\224\222 CryptoChat</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(card), title, FALSE, FALSE, 0);

    GtkWidget *sub = gtk_label_new("AES-256-CBC \342\200\224 End-to-end encrypted");
    gtk_style_context_add_class(gtk_widget_get_style_context(sub),
                                "login-subtitle");
    gtk_widget_set_halign(sub, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(card), sub, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(card),
        gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 6);

    /* Form */
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 14);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 14);

    GtkWidget *lbl;

    lbl = gtk_label_new("SERVER");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "field-label");
    gtk_widget_set_halign(lbl, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), lbl, 0, 0, 2, 1);

    app.host_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(app.host_entry), DEFAULT_HOST);
    gtk_widget_set_hexpand(app.host_entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid), app.host_entry, 0, 1, 1, 1);

    app.port_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(app.port_entry), DEFAULT_PORT);
    gtk_widget_set_size_request(app.port_entry, 90, -1);
    gtk_grid_attach(GTK_GRID(grid), app.port_entry, 1, 1, 1, 1);

    lbl = gtk_label_new("USERNAME");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "field-label");
    gtk_widget_set_halign(lbl, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), lbl, 0, 2, 2, 1);
    app.user_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app.user_entry), "e.g. alice");
    gtk_widget_set_hexpand(app.user_entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid), app.user_entry, 0, 3, 2, 1);

    lbl = gtk_label_new("PASSWORD");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "field-label");
    gtk_widget_set_halign(lbl, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), lbl, 0, 4, 2, 1);
    app.pass_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(app.pass_entry), FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(app.pass_entry), "Your password");
    gtk_entry_set_input_purpose(GTK_ENTRY(app.pass_entry),
                                GTK_INPUT_PURPOSE_PASSWORD);
    g_signal_connect(app.pass_entry, "activate",
                     G_CALLBACK(on_connect_clicked), NULL);
    gtk_widget_set_hexpand(app.pass_entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid), app.pass_entry, 0, 5, 2, 1);

    gtk_box_pack_start(GTK_BOX(card), grid, FALSE, FALSE, 0);

    /* Nút Connect & Signup */
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_set_homogeneous(GTK_BOX(btn_box), TRUE);

    app.connect_btn = gtk_button_new_with_label("Connect");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.connect_btn),
                                "connect-btn");
    g_signal_connect(app.connect_btn, "clicked",
                     G_CALLBACK(on_connect_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), app.connect_btn, TRUE, TRUE, 0);

    app.signup_btn = gtk_button_new_with_label("Sign Up");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.signup_btn),
                                "signup-btn");
    g_signal_connect(app.signup_btn, "clicked",
                     G_CALLBACK(on_signup_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), app.signup_btn, TRUE, TRUE, 0);

    gtk_box_pack_start(GTK_BOX(card), btn_box, FALSE, FALSE, 4);
    g_print("Signup button created: %p\n", app.signup_btn);

    /* Hàng trạng thái */
    GtkWidget *status_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(status_box, GTK_ALIGN_CENTER);

    app.login_spinner = gtk_spinner_new();
    gtk_box_pack_start(GTK_BOX(status_box), app.login_spinner, FALSE, FALSE, 0);

    app.login_status = gtk_label_new("Enter credentials to connect");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.login_status),
                                "login-subtitle");
    gtk_box_pack_start(GTK_BOX(status_box), app.login_status, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(card), status_box, FALSE, FALSE, 0);

    /* Gợi ý tài khoản demo */
    GtkWidget *hint = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(hint),
        "<span size='small' foreground='#3d4466'>"
        "Demo: alice/password123  \342\200\242  bob/secret456  \342\200\242  charlie/hello789"
        "</span>");
    gtk_widget_set_halign(hint, GTK_ALIGN_CENTER);
    gtk_label_set_line_wrap(GTK_LABEL(hint), TRUE);
    gtk_box_pack_start(GTK_BOX(card), hint, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(outer), card, FALSE, FALSE, 0);
    return outer;
}

/* ═══════════════════════════════════════════════════════════
 * Xây dựng trang Chat
 * ═══════════════════════════════════════════════════════════ */

/**
 * build_chat_page - Tạo widget giao diện cho màn hình chat.
 *
 * Hàm tạo:
 * - Sidebar: danh sách người dùng có signal on_user_activated.
 * - Vùng chat: TextView + TextBuffer + các text tags (setup_text_tags).
 * - Recipient bar: hiển thị khi đang chọn người dùng để gửi tin riêng (on_clear_pm).
 * - Khu nhập liệu: msg_entry (on_msg_activate) và send_btn (on_send_clicked).
 * - Status label để hiển thị trạng thái kết nối.
 *
 * Giá trị trả về:
 * - GtkWidget* gốc của màn hình chat (vbox).
 */
static GtkWidget *build_chat_page(void)
{
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_set_position(GTK_PANED(paned), 210);

    /* ── Sidebar ── */
    GtkWidget *sidebar = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(sidebar),
                                "sidebar");
    gtk_widget_set_size_request(sidebar, 190, -1);

    GtkWidget *sidebar_lbl = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(sidebar_lbl),
        "<span weight='bold'>ONLINE USERS</span>");
    gtk_style_context_add_class(gtk_widget_get_style_context(sidebar_lbl),
                                "sidebar-title");
    gtk_widget_set_halign(sidebar_lbl, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(sidebar), sidebar_lbl, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(sidebar),
        gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);

    GtkWidget *user_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(user_scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);

    app.user_list = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(app.user_list),
                                    GTK_SELECTION_SINGLE);
    g_signal_connect(app.user_list, "row-activated",
                     G_CALLBACK(on_user_activated), NULL);
    gtk_container_add(GTK_CONTAINER(user_scroll), app.user_list);
    gtk_box_pack_start(GTK_BOX(sidebar), user_scroll, TRUE, TRUE, 0);

    gtk_paned_pack1(GTK_PANED(paned), sidebar, FALSE, FALSE);

    /* ── Vùng Chat ── */
    GtkWidget *chat_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    /* Thanh PM (ẩn cho đến khi người dùng chọn người nhận) */
    app.recipient_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_style_context_add_class(gtk_widget_get_style_context(app.recipient_bar),
                                "pm-bar");

    GtkWidget *pm_icon = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(pm_icon),
        "<span foreground='#6fa3f7'>\342\234\211</span>");
    gtk_box_pack_start(GTK_BOX(app.recipient_bar), pm_icon, FALSE, FALSE, 6);

    /* Dùng markup để màu chữ không bị theme hệ thống override */
    app.recipient_label = gtk_label_new(NULL);
    gtk_box_pack_start(GTK_BOX(app.recipient_bar), app.recipient_label,
                       TRUE, TRUE, 0);

    GtkWidget *clear_btn = gtk_button_new_with_label("Cancel");
    g_signal_connect(clear_btn, "clicked", G_CALLBACK(on_clear_pm), NULL);
    gtk_box_pack_end(GTK_BOX(app.recipient_bar), clear_btn, FALSE, FALSE, 6);

    gtk_widget_set_no_show_all(app.recipient_bar, TRUE);
    gtk_box_pack_start(GTK_BOX(chat_box), app.recipient_bar, FALSE, FALSE, 0);

    /* Text view hiển thị chat */
    GtkWidget *chat_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(chat_scroll),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);

    app.chat_buf  = gtk_text_buffer_new(NULL);
    setup_text_tags();

    app.chat_view = gtk_text_view_new_with_buffer(app.chat_buf);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app.chat_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app.chat_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(app.chat_view),
                                GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(app.chat_view), 16);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(app.chat_view), 16);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(app.chat_view), 12);
    gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(app.chat_view), 12);

    GtkTextIter end_iter;
    gtk_text_buffer_get_end_iter(app.chat_buf, &end_iter);
    app.end_mark = gtk_text_buffer_create_mark(app.chat_buf, "end",
                                                &end_iter, FALSE);

    gtk_container_add(GTK_CONTAINER(chat_scroll), app.chat_view);
    gtk_box_pack_start(GTK_BOX(chat_box), chat_scroll, TRUE, TRUE, 0);

    /* Khu nhập liệu */
    GtkWidget *input_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_style_context_add_class(gtk_widget_get_style_context(input_box),
                                "msg-box");
    gtk_container_set_border_width(GTK_CONTAINER(input_box), 10);

    app.msg_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app.msg_entry),
                                   "Type a message... (/list  /msg user text  /quit)");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.msg_entry),
                                "msg-entry");
    gtk_widget_set_sensitive(app.msg_entry, FALSE);
    g_signal_connect(app.msg_entry, "activate",
                     G_CALLBACK(on_msg_activate), NULL);
    gtk_box_pack_start(GTK_BOX(input_box), app.msg_entry, TRUE, TRUE, 0);

    app.send_btn = gtk_button_new_with_label("Send");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.send_btn),
                                "send-btn");
    gtk_widget_set_sensitive(app.send_btn, FALSE);
    g_signal_connect(app.send_btn, "clicked",
                     G_CALLBACK(on_send_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(input_box), app.send_btn, FALSE, FALSE, 0);

    gtk_box_pack_end(GTK_BOX(chat_box), input_box, FALSE, FALSE, 0);

    gtk_paned_pack2(GTK_PANED(paned), chat_box, TRUE, TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), paned, TRUE, TRUE, 0);

    /* Thanh trạng thái */
    app.status_label = gtk_label_new("  Disconnected");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.status_label),
                                "statusbar");
    gtk_widget_set_halign(app.status_label, GTK_ALIGN_START);
    gtk_box_pack_end(GTK_BOX(vbox), app.status_label, FALSE, FALSE, 0);

    return vbox;
}

/* ═══════════════════════════════════════════════════════════
 * Nạp CSS
 * ═══════════════════════════════════════════════════════════ */

/**
 * setup_css - Nạp chuỗi CSS tích hợp (APP_CSS) vào GTK provider.
 *
 * Giá trị trả về: void.
 */
static void setup_css(void)
{
    GtkCssProvider *prov = gtk_css_provider_new();
    gtk_css_provider_load_from_data(prov, APP_CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(prov),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(prov);
}

/* ═══════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════ */

/**
 * main - Điểm khởi động ứng dụng GUI CryptoChat.
 *
 * Hành vi:
 * - Bỏ qua SIGPIPE để tránh crash khi ghi vào socket đã bị đóng.
 * - Khởi tạo memset struct app và gọi gtk_init().
 * - Nạp CSS, tạo header bar, cửa sổ chính và stack (login/chat).
 * - Điền trước host/port từ argv nếu có.
 * - Bắt đầu timer định kỳ làm mới danh sách người dùng online.
 * - Chạy gtk_main() vào vòng lặp sự kiện chính.
 *
 * Giá trị trả về:
 * - 0 khi thoát bình thường.
 */
int main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);

    memset(&app, 0, sizeof(app));
    app.sock      = -1;
    app.crypto.fd = -1;

    gtk_init(&argc, &argv);
    setup_css();

    /* Header bar */
    app.header_bar = gtk_header_bar_new();
    gtk_header_bar_set_title(GTK_HEADER_BAR(app.header_bar), "CryptoChat");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(app.header_bar),
                                "Secure Chat Application");
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(app.header_bar), TRUE);

    /* Cửa sổ chính */
    app.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_titlebar(GTK_WINDOW(app.window), app.header_bar);
    gtk_window_set_default_size(GTK_WINDOW(app.window), 980, 660);
    gtk_window_set_position(GTK_WINDOW(app.window), GTK_WIN_POS_CENTER);
    g_signal_connect(app.window, "destroy",
                     G_CALLBACK(on_window_destroy), NULL);

    /* Stack: login ↔ chat */
    app.stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(app.stack),
                                  GTK_STACK_TRANSITION_TYPE_SLIDE_LEFT);
    gtk_stack_set_transition_duration(GTK_STACK(app.stack), 300);

    gtk_stack_add_named(GTK_STACK(app.stack), build_login_page(), "login");
    gtk_stack_add_named(GTK_STACK(app.stack), build_chat_page(),  "chat");
    gtk_container_add(GTK_CONTAINER(app.window), app.stack);

    /* Điền trước host/port từ tham số dòng lệnh */
    if (argc >= 2)
        gtk_entry_set_text(GTK_ENTRY(app.host_entry), argv[1]);
    if (argc >= 3)
        gtk_entry_set_text(GTK_ENTRY(app.port_entry), argv[2]);

    /* Timer định kỳ làm mới danh sách người dùng */
    app.list_timer_id = g_timeout_add_seconds(LIST_INTERVAL_SEC,
                                               on_list_timer, NULL);

    gtk_widget_show_all(app.window);
    gtk_stack_set_visible_child_name(GTK_STACK(app.stack), "login");

    gtk_main();
    return 0;
}