/* =============================================================================
 * app_state.h — Shared application state, types, and forward declarations
 *               for the CryptoChat GUI client.
 * ============================================================================= */
#ifndef APP_STATE_H
#define APP_STATE_H

#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <pango/pango.h>
#include <stdint.h>
#include <pthread.h>

#include "../../crypto_lib.h"

/* ── Configuration ───────────────────────────────────────── */
#define DEFAULT_HOST        "127.0.0.1"
#define DEFAULT_PORT        "9090"
#define SHARED_SECRET       "CryptoChatServerSecret_v1_DO_NOT_SHARE"
#define LIST_INTERVAL_SEC   15
#define SERVER_HISTORY_LIMIT 8

/* ── UI message types (internal) ─────────────────────────── */
enum {
    UI_MSG_NORMAL,
    UI_MSG_SYSTEM,
    UI_MSG_PRIVATE,
    UI_MSG_ERROR,
    UI_MSG_USERLIST,
    UI_MSG_PASSWD_OK,
    UI_MSG_PASSWD_FAIL
};

/* ── Application state ───────────────────────────────────── */
typedef struct {
    /* Login page */
    GtkWidget    *window;
    GtkWidget    *stack;
    GtkWidget    *host_entry;
    GtkWidget    *port_entry;
    GtkListStore *host_history_store;
    GtkListStore *port_history_store;
    GtkWidget    *user_entry;
    GtkWidget    *pass_entry;
    GtkWidget    *connect_btn;
    GtkWidget    *signup_btn;
    GtkWidget    *login_status;
    GtkWidget    *login_spinner;

    /* Chat page */
    GtkWidget    *header_bar;
    GtkWidget    *change_pass_btn;
    GtkWidget    *logout_btn;
    GtkWidget    *chat_view;
    GtkTextBuffer*chat_buf;
    GtkTextMark  *end_mark;
    GtkWidget    *msg_entry;
    GtkWidget    *emoji_btn;
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

    /* Network */
    int           sock;
    char          username[MAX_USERNAME_LEN];
    char          recipient[MAX_USERNAME_LEN];
    uint8_t       current_password_hash[SHA256_DIGEST_SIZE];
    uint8_t       pending_password_hash[SHA256_DIGEST_SIZE];
    int           has_password_hash;
    int           has_pending_password_hash;
    uint8_t       session_key[AES_KEY_SIZE];
    crypto_ctx_t  crypto;
    volatile int  connected;
    pthread_t     rx_tid;
    guint         list_timer_id;
    guint         reconnect_timer_id;

    /* Last connection info for auto-reconnect */
    char          last_host[256];
    int           last_port;
    char          last_pass[MAX_PASSWORD_LEN];
    int           reconnecting;

    /* Message storage & view */
    GPtrArray    *messages;
    char          current_view[MAX_USERNAME_LEN]; /* "" = public, "user" = private */
} App;

extern App app;

/* ── Thread argument types ───────────────────────────────── */
typedef struct {
    char host[256];
    int  port;
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
} ConnectArgs;

typedef struct {
    int   type;
    char *text;
    char *peer;  /* NULL/"" = public, "username" = private with that user */
} UIMsgData;

typedef struct {
    int   type;
    char *text;
    char *peer;
} ChatMessage;

typedef struct {
    char host[256];
    int  port;
} ServerHistoryArgs;

/* ── gui.c — Page builders ───────────────────────────────── */
GtkWidget *build_login_page(void);
GtkWidget *build_chat_page(void);
void       setup_text_tags(void);

/* ── ui_callbacks.c — GTK signal handlers & UI updates ──── */
void     on_connect_clicked(GtkWidget *w, gpointer data);
void     on_signup_clicked(GtkWidget *w, gpointer data);
void     on_send_clicked(GtkWidget *w, gpointer data);
void     on_msg_activate(GtkWidget *w, gpointer data);
void     on_emoji_clicked(GtkWidget *w, gpointer data);
void     on_emoji_selected(GtkWidget *w, gpointer data);
void     on_user_activated(GtkListBox *lb, GtkListBoxRow *row, gpointer data);
void     on_clear_pm(GtkWidget *w, gpointer data);
void     on_change_password_clicked(GtkWidget *w, gpointer data);
void     on_logout_clicked(GtkWidget *w, gpointer data);
void     on_window_destroy(GtkWidget *w, gpointer data);
gboolean on_list_timer(gpointer data);
gboolean on_reconnect_timer(gpointer data);
void     perform_logout(gboolean notify_server, const char *login_msg);

void     append_chat_text(const char *text, int msg_type);
void     show_message_dialog(GtkMessageType msg_type, const char *text);
void     store_and_show_message(const char *text, int type, const char *peer);
void     rebuild_chat_view(void);

gboolean ui_on_message(gpointer data);
gboolean ui_on_disconnect(gpointer data);
gboolean ui_connect_ok(gpointer data);
gboolean ui_connect_fail(gpointer data);
gboolean ui_connect_success(gpointer data);

/* ── network.c — Networking, auth & threads ──────────────── */
int   send_command(uint8_t type, const void *payload, uint16_t plain_len);
int   send_chat(const char *recipient, const char *message);
void *connect_thread_func(void *data);
void *signup_thread_func(void *data);

/* ── history.c — Server history management ───────────────── */
void load_server_history(void);
void apply_startup_server_defaults(int argc, char *argv[]);
void queue_server_history(const char *host, int port);

#endif /* APP_STATE_H */
