/* =============================================================================
 * ui_callbacks.c — GTK signal handlers, idle callbacks & UI update functions
 * ============================================================================= */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "../include/app_state.h"


/* ═══════════════════════════════════════════════════════════
 * Message storage & view switching
 * ═══════════════════════════════════════════════════════════ */

static void free_chat_message(ChatMessage *m)
{
    if (!m) return;
    g_free(m->text);
    g_free(m->peer);
    g_free(m);
}

static gboolean should_show_in_view(int type, const char *peer)
{
    (void)type;
    if (app.current_view[0] == '\0') {
        /* Public view: show broadcasts, system, normal — NOT private */
        return (peer == NULL || peer[0] == '\0');
    } else {
        /* Private view: show only messages with this specific peer */
        return (peer != NULL && strcmp(peer, app.current_view) == 0);
    }
}

void store_and_show_message(const char *text, int type, const char *peer)
{
    ChatMessage *msg = g_new0(ChatMessage, 1);
    msg->type = type;
    msg->text = g_strdup(text);
    msg->peer = g_strdup(peer);
    g_ptr_array_add(app.messages, msg);

    if (should_show_in_view(type, peer))
        append_chat_text(text, type);
}

void rebuild_chat_view(void)
{
    /* Clear buffer */
    GtkTextIter start, end;
    gtk_text_buffer_get_start_iter(app.chat_buf, &start);
    gtk_text_buffer_get_end_iter(app.chat_buf, &end);
    gtk_text_buffer_delete(app.chat_buf, &start, &end);

    /* Re-insert matching messages */
    for (guint i = 0; i < app.messages->len; i++) {
        ChatMessage *m = g_ptr_array_index(app.messages, i);
        if (should_show_in_view(m->type, m->peer))
            append_chat_text(m->text, m->type);
    }
}

static void clear_all_messages(void)
{
    for (guint i = 0; i < app.messages->len; i++)
        free_chat_message(g_ptr_array_index(app.messages, i));
    g_ptr_array_set_size(app.messages, 0);
}


/* ═══════════════════════════════════════════════════════════
 * Utility dialogs
 * ═══════════════════════════════════════════════════════════ */

void show_message_dialog(GtkMessageType msg_type, const char *text)
{
    GtkWidget *dlg = gtk_message_dialog_new(
        GTK_WINDOW(app.window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        msg_type,
        GTK_BUTTONS_OK,
        "%s",
        text ? text : "");
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}


/* ═══════════════════════════════════════════════════════════
 * Chat text & user list updates
 * ═══════════════════════════════════════════════════════════ */

void append_chat_text(const char *text, int msg_type)
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
    default:
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
    
    /* Use a hash table to count unique usernames for the status bar */
    GHashTable *unique_users = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    while (token) {
        while (*token == ' ') token++;
        char *tail = token + strlen(token) - 1;
        while (tail > token && *tail == ' ') *tail-- = '\0';

        if (!*token) { token = strtok_r(NULL, ",", &saveptr); continue; }

        /* Add to unique set for count */
        g_hash_table_add(unique_users, g_strdup(token));

        char buf[128];
        gboolean is_self = (strcmp(token, app.username) == 0);
        if (is_self)
            snprintf(buf, sizeof(buf), "  \xe2\x97\x8f  %s  (you)", token);
        else
            snprintf(buf, sizeof(buf), "  \xe2\x97\x8f  %s", token);

        GtkWidget *lbl = gtk_label_new(buf);
        gtk_widget_set_halign(lbl, GTK_ALIGN_START);
        gtk_style_context_add_class(gtk_widget_get_style_context(lbl),
                                    is_self ? "user-row user-row-self" : "user-row");
        g_object_set_data_full(G_OBJECT(lbl), "uname",
                                g_strdup(token), g_free);

        gtk_list_box_insert(GTK_LIST_BOX(app.user_list), lbl, -1);
        gtk_widget_show_all(lbl);
        token = strtok_r(NULL, ",", &saveptr);
    }
    
    int unique_count = (int)g_hash_table_size(unique_users);
    g_hash_table_destroy(unique_users);
    g_free(copy);

    char status[256];
    snprintf(status, sizeof(status),
             "  \xf0\x9f\x94\x90 AES-256-CBC  \xe2\x80\x94  \xe2\x9a\xa1 Connected  \xe2\x80\x94  %d user%s online",
             unique_count, unique_count == 1 ? "" : "s");
    gtk_label_set_text(GTK_LABEL(app.status_label), status);
}


/* ═══════════════════════════════════════════════════════════
 * Idle callbacks (pushed from receiver thread)
 * ═══════════════════════════════════════════════════════════ */

gboolean ui_on_message(gpointer data)
{
    UIMsgData *d = data;

    if (d->type == UI_MSG_USERLIST) {
        update_user_list(d->text);
    } else if (d->type == UI_MSG_PASSWD_OK) {
        if (app.has_pending_password_hash) {
            memcpy(app.current_password_hash,
                   app.pending_password_hash,
                   SHA256_DIGEST_SIZE);
            app.has_password_hash = 1;
            app.has_pending_password_hash = 0;
            memset(app.pending_password_hash, 0,
                   sizeof(app.pending_password_hash));
        }
        show_message_dialog(GTK_MESSAGE_INFO, d->text);
        store_and_show_message(d->text, UI_MSG_SYSTEM, NULL);
    } else if (d->type == UI_MSG_PASSWD_FAIL) {
        app.has_pending_password_hash = 0;
        memset(app.pending_password_hash, 0,
               sizeof(app.pending_password_hash));
        show_message_dialog(GTK_MESSAGE_WARNING, d->text);
        store_and_show_message(d->text, UI_MSG_ERROR, NULL);
    } else {
        store_and_show_message(d->text, d->type, d->peer);
    }

    g_free(d->text);
    g_free(d->peer);
    g_free(d);
    return G_SOURCE_REMOVE;
}

gboolean ui_on_disconnect(gpointer data)
{
    (void)data;
    if (app.reconnecting) return G_SOURCE_REMOVE;

    store_and_show_message("[!] Connection lost. Attempting to reconnect...", UI_MSG_ERROR, NULL);
    
    app.connected = 0;
    app.reconnecting = 1;
    
    gtk_widget_set_sensitive(app.msg_entry, FALSE);
    gtk_widget_set_sensitive(app.send_btn, FALSE);
    gtk_widget_set_sensitive(app.emoji_btn, FALSE);
    
    gtk_label_set_text(GTK_LABEL(app.status_label),
                       "  Connection lost \xe2\x80\x94 Attempting to reconnect...");

    /* Start reconnect timer: every 5 seconds */
    if (app.reconnect_timer_id == 0) {
        app.reconnect_timer_id = g_timeout_add_seconds(5, on_reconnect_timer, NULL);
    }

    return G_SOURCE_REMOVE;
}

gboolean on_reconnect_timer(gpointer data)
{
    (void)data;
    if (app.connected) {
        app.reconnect_timer_id = 0;
        return G_SOURCE_REMOVE;
    }

    /* Try to connect again in a thread */
    ConnectArgs *args = g_new0(ConnectArgs, 1);
    snprintf(args->host, sizeof(args->host), "%s", app.last_host);
    args->port = app.last_port;
    snprintf(args->username, sizeof(args->username), "%s", app.username);
    snprintf(args->password, sizeof(args->password), "%s", app.last_pass);

    pthread_t tid;
    pthread_create(&tid, NULL, connect_thread_func, args);
    pthread_detach(tid);

    return G_SOURCE_CONTINUE;
}

gboolean ui_connect_ok(gpointer data)
{
    char *host_info = (char *)data;

    if (app.reconnect_timer_id > 0) {
        g_source_remove(app.reconnect_timer_id);
        app.reconnect_timer_id = 0;
    }
    app.reconnecting = 0;

    /* Init to public view */
    memset(app.current_view, 0, sizeof(app.current_view));
    gtk_widget_hide(app.recipient_bar);

    gtk_stack_set_visible_child_name(GTK_STACK(app.stack), "chat");

    char title[256];
    snprintf(title, sizeof(title), "CryptoChat \xe2\x80\x94 %s@%s",
             app.username, host_info);
    gtk_header_bar_set_title(GTK_HEADER_BAR(app.header_bar), title);
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(app.header_bar),
                                 "AES-256-CBC + SHA-256 Encrypted");

    gtk_widget_set_sensitive(app.msg_entry, TRUE);
    gtk_widget_set_sensitive(app.emoji_btn, TRUE);
    gtk_widget_set_sensitive(app.send_btn, TRUE);
    if (app.change_pass_btn) {
        gtk_widget_show(app.change_pass_btn);
        gtk_widget_set_sensitive(app.change_pass_btn, TRUE);
    }
    if (app.logout_btn) {
        gtk_widget_show(app.logout_btn);
        gtk_widget_set_sensitive(app.logout_btn, TRUE);
    }
    gtk_widget_grab_focus(app.msg_entry);

    store_and_show_message("Connected. All messages are encrypted with AES-256-CBC.",
                           UI_MSG_SYSTEM, NULL);

    g_free(host_info);
    return G_SOURCE_REMOVE;
}

gboolean ui_connect_fail(gpointer data)
{
    char *msg = (char *)data;
    gtk_style_context_remove_class(
        gtk_widget_get_style_context(app.login_status), "success-status");
    gtk_label_set_text(GTK_LABEL(app.login_status), msg);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.login_status), "error-status");

    gtk_widget_set_sensitive(app.connect_btn, TRUE);
    gtk_widget_set_sensitive(app.signup_btn, TRUE);
    gtk_spinner_stop(GTK_SPINNER(app.login_spinner));

    g_free(msg);
    return G_SOURCE_REMOVE;
}

gboolean ui_connect_success(gpointer data)
{
    char *msg = (char *)data;
    gtk_style_context_remove_class(
        gtk_widget_get_style_context(app.login_status), "error-status");
    gtk_label_set_text(GTK_LABEL(app.login_status), msg);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.login_status), "success-status");

    gtk_widget_set_sensitive(app.connect_btn, TRUE);
    gtk_widget_set_sensitive(app.signup_btn, TRUE);
    gtk_spinner_stop(GTK_SPINNER(app.login_spinner));

    g_free(msg);
    return G_SOURCE_REMOVE;
}


/* ═══════════════════════════════════════════════════════════
 * GTK Signal Handlers
 * ═══════════════════════════════════════════════════════════ */

void on_send_clicked(GtkWidget *w, gpointer data)
{
    (void)w; (void)data;
    if (!app.connected) return;

    const char *text = gtk_entry_get_text(GTK_ENTRY(app.msg_entry));
    if (!text[0]) return;

    /* Send to current_view: "" = broadcast, "user" = private */
    send_chat(app.current_view, text);

    gtk_entry_set_text(GTK_ENTRY(app.msg_entry), "");
    gtk_widget_grab_focus(app.msg_entry);
}

void on_connect_clicked(GtkWidget *w, gpointer data)
{
    (void)w; (void)data;
    const char *host     = gtk_entry_get_text(GTK_ENTRY(app.host_entry));
    const char *port_str = gtk_entry_get_text(GTK_ENTRY(app.port_entry));
    const char *user     = gtk_entry_get_text(GTK_ENTRY(app.user_entry));
    const char *pass     = gtk_entry_get_text(GTK_ENTRY(app.pass_entry));

    if (!user[0] || !pass[0]) {
        gtk_label_set_text(GTK_LABEL(app.login_status),
                           "Username and password are required");
        gtk_style_context_remove_class(
            gtk_widget_get_style_context(app.login_status), "success-status");
        gtk_style_context_add_class(
            gtk_widget_get_style_context(app.login_status), "error-status");
        return;
    }

    gtk_style_context_remove_class(
        gtk_widget_get_style_context(app.login_status), "error-status");
    gtk_style_context_remove_class(
        gtk_widget_get_style_context(app.login_status), "success-status");
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

void on_signup_clicked(GtkWidget *w, gpointer data)
{
    (void)w; (void)data;
    const char *host     = gtk_entry_get_text(GTK_ENTRY(app.host_entry));
    const char *port_str = gtk_entry_get_text(GTK_ENTRY(app.port_entry));
    const char *user     = gtk_entry_get_text(GTK_ENTRY(app.user_entry));
    const char *pass     = gtk_entry_get_text(GTK_ENTRY(app.pass_entry));

    if (!user[0] || !pass[0]) {
        gtk_label_set_text(GTK_LABEL(app.login_status), "Username and password required");
        gtk_style_context_remove_class(
            gtk_widget_get_style_context(app.login_status), "success-status");
        gtk_style_context_add_class(
            gtk_widget_get_style_context(app.login_status), "error-status");
        return;
    }

    gtk_style_context_remove_class(
        gtk_widget_get_style_context(app.login_status), "error-status");
    gtk_style_context_remove_class(
        gtk_widget_get_style_context(app.login_status), "success-status");
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

void on_msg_activate(GtkWidget *w, gpointer data)
{
    (void)w; (void)data;
    on_send_clicked(NULL, NULL);
}

void on_emoji_clicked(GtkWidget *w, gpointer data)
{
    (void)data;
    static GtkWidget *popover = NULL;

    if (!popover) {
        popover = gtk_popover_new(w);
        GtkWidget *grid = gtk_grid_new();
        gtk_grid_set_row_spacing(GTK_GRID(grid), 2);
        gtk_grid_set_column_spacing(GTK_GRID(grid), 2);
        gtk_container_set_border_width(GTK_CONTAINER(grid), 6);

        const char *emojis[] = {
            "\xf0\x9f\x98\x80", "\xf0\x9f\x98\x81", "\xf0\x9f\x98\x82", "\xf0\x9f\x98\x83",
            "\xf0\x9f\x98\x84", "\xf0\x9f\x98\x85", "\xf0\x9f\x98\x86", "\xf0\x9f\x98\x89",
            "\xf0\x9f\x98\x8d", "\xf0\x9f\x98\x98", "\xf0\x9f\x98\x8b", "\xf0\x9f\x98\x8e",
            "\xf0\x9f\x98\x94", "\xf0\x9f\x98\xb3", "\xf0\x9f\x98\xb1", "\xf0\x9f\x98\xa1",
            "\xf0\x9f\x91\x8d", "\xf0\x9f\x91\x8e", "\xf0\x9f\x91\x8c", "\xf0\x9f\x99\x8f",
            "\xe2\x9d\xa4", "\xf0\x9f\x94\xa5", "\xe2\x9c\xa8", "\xf0\x9f\x92\xa9"
        };
        int cols = 6;
        for (int i = 0; i < 24; i++) {
            GtkWidget *btn = gtk_button_new_with_label(emojis[i]);
            gtk_button_set_relief(GTK_BUTTON(btn), GTK_RELIEF_NONE);
            g_object_set_data(G_OBJECT(btn), "emoji", (gpointer)emojis[i]);
            g_signal_connect(btn, "clicked", G_CALLBACK(on_emoji_selected), popover);
            gtk_grid_attach(GTK_GRID(grid), btn, i % cols, i / cols, 1, 1);
        }
        gtk_container_add(GTK_CONTAINER(popover), grid);
        gtk_widget_show_all(grid);
    }
    gtk_popover_popup(GTK_POPOVER(popover));
}

void on_emoji_selected(GtkWidget *w, gpointer data)
{
    GtkWidget *popover = (GtkWidget *)data;
    const char *emoji = (const char *)g_object_get_data(G_OBJECT(w), "emoji");
    
    int pos = gtk_editable_get_position(GTK_EDITABLE(app.msg_entry));
    gtk_editable_insert_text(GTK_EDITABLE(app.msg_entry), emoji, -1, &pos);
    gtk_editable_set_position(GTK_EDITABLE(app.msg_entry), pos);

    gtk_popover_popdown(GTK_POPOVER(popover));
    gtk_widget_grab_focus(app.msg_entry);
}

void on_user_activated(GtkListBox *lb, GtkListBoxRow *row, gpointer data)
{
    (void)lb; (void)data;
    if (!row) return;

    GtkWidget  *child = gtk_bin_get_child(GTK_BIN(row));
    const char *name  = (const char *)g_object_get_data(G_OBJECT(child), "uname");
    if (!name) return;

    if (strcmp(name, app.username) == 0) {
        /* Click own name → public view */
        memset(app.current_view, 0, sizeof(app.current_view));
        gtk_widget_hide(app.recipient_bar);
    } else {
        /* Click another user → private view with that person */
        snprintf(app.current_view, sizeof(app.current_view), "%s", name);

        char *markup = g_strdup_printf(
            "<span foreground='#6fa3f7' weight='bold' size='small'>"
            "\xe2\x9c\x89  Private chat with: %s"
            "</span>"
            "<span foreground='#4a5a80' size='small'>"
            "  (click your name to go back to public)"
            "</span>",
            name);
        gtk_label_set_markup(GTK_LABEL(app.recipient_label), markup);
        gtk_widget_show(app.recipient_bar);
        g_free(markup);
    }

    rebuild_chat_view();
}

void on_clear_pm(GtkWidget *w, gpointer data)
{
    (void)w; (void)data;
    /* Back to public view */
    memset(app.current_view, 0, sizeof(app.current_view));
    gtk_widget_hide(app.recipient_bar);
    rebuild_chat_view();
}

void on_change_password_clicked(GtkWidget *w, gpointer data)
{
    (void)w; (void)data;
    GtkWidget *dialog = gtk_dialog_new_with_buttons(
        "Change Password", GTK_WINDOW(app.window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "Cancel", GTK_RESPONSE_CANCEL,
        "Change", GTK_RESPONSE_OK, NULL);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *grid = gtk_grid_new();
    GtkWidget *old_entry = gtk_entry_new();
    GtkWidget *new_entry = gtk_entry_new();
    GtkWidget *confirm_entry = gtk_entry_new();
    struct passwd_change_payload pp;

    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 12);

    gtk_entry_set_visibility(GTK_ENTRY(old_entry), FALSE);
    gtk_entry_set_visibility(GTK_ENTRY(new_entry), FALSE);
    gtk_entry_set_visibility(GTK_ENTRY(confirm_entry), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(old_entry), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_input_purpose(GTK_ENTRY(new_entry), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_input_purpose(GTK_ENTRY(confirm_entry), GTK_INPUT_PURPOSE_PASSWORD);

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Old Password"), 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), old_entry, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("New Password"), 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), new_entry, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Retype New Password"), 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), confirm_entry, 1, 2, 1, 1);

    gtk_box_pack_start(GTK_BOX(content), grid, TRUE, TRUE, 0);
    gtk_widget_show_all(content);

    while (1) {
        int resp = gtk_dialog_run(GTK_DIALOG(dialog));
        if (resp != GTK_RESPONSE_OK) break;

        const char *old_pass = gtk_entry_get_text(GTK_ENTRY(old_entry));
        const char *new_pass = gtk_entry_get_text(GTK_ENTRY(new_entry));
        const char *confirm  = gtk_entry_get_text(GTK_ENTRY(confirm_entry));
        uint8_t old_hash[SHA256_DIGEST_SIZE];
        uint8_t new_hash[SHA256_DIGEST_SIZE];

        if (!old_pass[0]) {
            show_message_dialog(GTK_MESSAGE_WARNING, "Please enter your old password.");
            continue;
        }
        if (!app.has_password_hash) {
            show_message_dialog(GTK_MESSAGE_WARNING, "Cannot verify — please reconnect.");
            continue;
        }
        if (crypto_sha256(&app.crypto, (const uint8_t *)old_pass,
                          (uint32_t)strlen(old_pass), old_hash) < 0) {
            show_message_dialog(GTK_MESSAGE_ERROR, "Crypto driver error.");
            continue;
        }
        if (memcmp(old_hash, app.current_password_hash, SHA256_DIGEST_SIZE) != 0) {
            show_message_dialog(GTK_MESSAGE_WARNING, "Old password is incorrect.");
            gtk_widget_grab_focus(old_entry);
            continue;
        }
        if (!new_pass[0] || !confirm[0]) {
            show_message_dialog(GTK_MESSAGE_WARNING, "Please enter both new password fields.");
            continue;
        }
        if (strcmp(new_pass, confirm) != 0) {
            show_message_dialog(GTK_MESSAGE_WARNING, "New passwords do not match.");
            continue;
        }
        if (!app.connected) {
            show_message_dialog(GTK_MESSAGE_WARNING, "Not connected.");
            break;
        }

        memset(&pp, 0, sizeof(pp));
        if (crypto_sha256(&app.crypto, (const uint8_t *)new_pass,
                          (uint32_t)strlen(new_pass), new_hash) < 0) {
            show_message_dialog(GTK_MESSAGE_ERROR, "Crypto driver error.");
            break;
        }
        memcpy(pp.old_password_hash, old_hash, SHA256_DIGEST_SIZE);
        memcpy(pp.new_password_hash, new_hash, SHA256_DIGEST_SIZE);

        if (send_command(MSG_TYPE_PASSWD_CHANGE_REQ, &pp, sizeof(pp)) < 0) {
            show_message_dialog(GTK_MESSAGE_ERROR, "Send failed.");
            break;
        }
        memcpy(app.pending_password_hash, new_hash, SHA256_DIGEST_SIZE);
        app.has_pending_password_hash = 1;
        store_and_show_message("Password change request sent...", UI_MSG_SYSTEM, NULL);
        break;
    }
    gtk_widget_destroy(dialog);
}

gboolean on_list_timer(gpointer data)
{
    (void)data;
    if (app.connected)
        send_command(MSG_TYPE_LIST, "", 0);
    return G_SOURCE_CONTINUE;
}

void perform_logout(gboolean notify_server, const char *login_msg)
{
    if (app.connected && notify_server)
        send_command(MSG_TYPE_LOGOUT, "bye", 3);

    if (app.reconnect_timer_id > 0) {
        g_source_remove(app.reconnect_timer_id);
        app.reconnect_timer_id = 0;
    }
    app.reconnecting = 0;

    app.connected = 0;
    app.has_password_hash = 0;
    app.has_pending_password_hash = 0;
    memset(app.current_password_hash, 0, sizeof(app.current_password_hash));
    memset(app.pending_password_hash, 0, sizeof(app.pending_password_hash));
    memset(app.last_pass, 0, sizeof(app.last_pass));

    if (app.sock >= 0) {
        shutdown(app.sock, SHUT_RDWR);
        close(app.sock);
        app.sock = -1;
    }

    crypto_close(&app.crypto);
    memset(app.session_key, 0, sizeof(app.session_key));
    memset(app.username, 0, sizeof(app.username));
    memset(app.recipient, 0, sizeof(app.recipient));
    memset(app.current_view, 0, sizeof(app.current_view));

    /* Clear stored messages */
    clear_all_messages();

    gtk_widget_set_sensitive(app.msg_entry, FALSE);
    gtk_widget_set_sensitive(app.emoji_btn, FALSE);
    gtk_widget_set_sensitive(app.send_btn, FALSE);
    if (app.change_pass_btn) {
        gtk_widget_set_sensitive(app.change_pass_btn, FALSE);
        gtk_widget_hide(app.change_pass_btn);
    }
    if (app.logout_btn) {
        gtk_widget_set_sensitive(app.logout_btn, FALSE);
        gtk_widget_hide(app.logout_btn);
    }
    gtk_widget_hide(app.recipient_bar);
    gtk_entry_set_text(GTK_ENTRY(app.msg_entry), "");

    GList *children = gtk_container_get_children(GTK_CONTAINER(app.user_list));
    for (GList *l = children; l; l = l->next)
        gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(children);

    gtk_label_set_text(GTK_LABEL(app.status_label), "  Disconnected");
    gtk_header_bar_set_title(GTK_HEADER_BAR(app.header_bar), "CryptoChat");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(app.header_bar),
                                "Secure Chat Application");

    if (login_msg) {
        gtk_style_context_remove_class(
            gtk_widget_get_style_context(app.login_status), "error-status");
        gtk_style_context_add_class(
            gtk_widget_get_style_context(app.login_status), "success-status");
        gtk_label_set_text(GTK_LABEL(app.login_status), login_msg);
    }

    gtk_spinner_stop(GTK_SPINNER(app.login_spinner));
    gtk_widget_set_sensitive(app.connect_btn, TRUE);
    gtk_widget_set_sensitive(app.signup_btn, TRUE);

    gtk_stack_set_visible_child_name(GTK_STACK(app.stack), "login");
    gtk_widget_grab_focus(app.user_entry);
}

void on_logout_clicked(GtkWidget *w, gpointer data)
{
    (void)w; (void)data;
    perform_logout(TRUE, "Logged out. Please sign in again.");
}

void on_window_destroy(GtkWidget *w, gpointer data)
{
    (void)w; (void)data;
    if (app.list_timer_id > 0) {
        g_source_remove(app.list_timer_id);
        app.list_timer_id = 0;
    }
    perform_logout(TRUE, NULL);
    gtk_main_quit();
}
