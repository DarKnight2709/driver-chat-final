/* =============================================================================
 * gui.c — Login page and chat page widget builders
 * ============================================================================= */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <pango/pango.h>

#include "../include/app_state.h"

void setup_text_tags(void)
{
    app.tag_time = gtk_text_buffer_create_tag(app.chat_buf, "time",
        "foreground", "#4a5580", "scale", 0.9, NULL);
    app.tag_system = gtk_text_buffer_create_tag(app.chat_buf, "system",
        "foreground", "#e8a742", "style", PANGO_STYLE_ITALIC, NULL);
    app.tag_private = gtk_text_buffer_create_tag(app.chat_buf, "private",
        "foreground", "#ffffff", "weight", PANGO_WEIGHT_BOLD, NULL);
    app.tag_error = gtk_text_buffer_create_tag(app.chat_buf, "error",
        "foreground", "#f47067", "weight", PANGO_WEIGHT_BOLD, NULL);
    app.tag_join = gtk_text_buffer_create_tag(app.chat_buf, "join",
        "foreground", "#4ec97e", "style", PANGO_STYLE_ITALIC, NULL);
    app.tag_sender = gtk_text_buffer_create_tag(app.chat_buf, "sender",
        "foreground", "#6fa3f7", "weight", PANGO_WEIGHT_BOLD, NULL);
    app.tag_self = gtk_text_buffer_create_tag(app.chat_buf, "self",
        "foreground", "#4ec97e", NULL);
}

GtkWidget *build_login_page(void)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_halign(outer, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(outer, GTK_ALIGN_CENTER);

    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 18);
    gtk_style_context_add_class(gtk_widget_get_style_context(card), "login-card");
    gtk_widget_set_size_request(card, 440, -1);
    gtk_container_set_border_width(GTK_CONTAINER(card), 40);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title),
        "<span size='xx-large' weight='bold' foreground='#dde3f5'>"
        "\xf0\x9f\x94\x92 CryptoChat</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(card), title, FALSE, FALSE, 0);

    GtkWidget *sub = gtk_label_new("AES-256-CBC \xe2\x80\x94 End-to-end encrypted");
    gtk_style_context_add_class(gtk_widget_get_style_context(sub), "login-subtitle");
    gtk_widget_set_halign(sub, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(card), sub, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(card),
        gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 6);

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
    gtk_entry_set_input_purpose(GTK_ENTRY(app.pass_entry), GTK_INPUT_PURPOSE_PASSWORD);
    g_signal_connect(app.pass_entry, "activate", G_CALLBACK(on_connect_clicked), NULL);
    gtk_widget_set_hexpand(app.pass_entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid), app.pass_entry, 0, 5, 2, 1);

    load_server_history();
    gtk_box_pack_start(GTK_BOX(card), grid, FALSE, FALSE, 0);

    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_set_homogeneous(GTK_BOX(btn_box), TRUE);

    app.connect_btn = gtk_button_new_with_label("Connect");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.connect_btn), "connect-btn");
    g_signal_connect(app.connect_btn, "clicked", G_CALLBACK(on_connect_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), app.connect_btn, TRUE, TRUE, 0);

    app.signup_btn = gtk_button_new_with_label("Sign Up");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.signup_btn), "signup-btn");
    g_signal_connect(app.signup_btn, "clicked", G_CALLBACK(on_signup_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), app.signup_btn, TRUE, TRUE, 0);

    gtk_box_pack_start(GTK_BOX(card), btn_box, FALSE, FALSE, 4);
    g_print("Signup button created: %p\n", app.signup_btn);

    GtkWidget *status_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(status_box, GTK_ALIGN_CENTER);
    app.login_spinner = gtk_spinner_new();
    gtk_box_pack_start(GTK_BOX(status_box), app.login_spinner, FALSE, FALSE, 0);
    app.login_status = gtk_label_new("Enter credentials to connect");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.login_status), "login-subtitle");
    gtk_box_pack_start(GTK_BOX(status_box), app.login_status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(card), status_box, FALSE, FALSE, 0);

    GtkWidget *hint = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(hint),
        "<span size='small' foreground='#3d4466'>"
        "Demo: alice/password123  \xe2\x80\xa2  bob/secret456  \xe2\x80\xa2  charlie/hello789"
        "</span>");
    gtk_widget_set_halign(hint, GTK_ALIGN_CENTER);
    gtk_label_set_line_wrap(GTK_LABEL(hint), TRUE);
    gtk_box_pack_start(GTK_BOX(card), hint, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(outer), card, FALSE, FALSE, 0);
    return outer;
}

GtkWidget *build_chat_page(void)
{
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_set_position(GTK_PANED(paned), 210);

    /* Sidebar */
    GtkWidget *sidebar = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(sidebar), "sidebar");
    gtk_widget_set_size_request(sidebar, 190, -1);

    GtkWidget *sidebar_lbl = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(sidebar_lbl), "<span weight='bold'>ONLINE USERS</span>");
    gtk_style_context_add_class(gtk_widget_get_style_context(sidebar_lbl), "sidebar-title");
    gtk_widget_set_halign(sidebar_lbl, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(sidebar), sidebar_lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sidebar),
        gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);

    GtkWidget *user_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(user_scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    app.user_list = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(app.user_list), GTK_SELECTION_SINGLE);
    g_signal_connect(app.user_list, "row-activated", G_CALLBACK(on_user_activated), NULL);
    gtk_container_add(GTK_CONTAINER(user_scroll), app.user_list);
    gtk_box_pack_start(GTK_BOX(sidebar), user_scroll, TRUE, TRUE, 0);
    gtk_paned_pack1(GTK_PANED(paned), sidebar, FALSE, FALSE);

    /* Chat area */
    GtkWidget *chat_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    app.recipient_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_style_context_add_class(gtk_widget_get_style_context(app.recipient_bar), "pm-bar");
    GtkWidget *pm_icon = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(pm_icon), "<span foreground='#6fa3f7'>\xe2\x9c\x89</span>");
    gtk_box_pack_start(GTK_BOX(app.recipient_bar), pm_icon, FALSE, FALSE, 6);
    app.recipient_label = gtk_label_new(NULL);
    gtk_box_pack_start(GTK_BOX(app.recipient_bar), app.recipient_label, TRUE, TRUE, 0);
    GtkWidget *clear_btn = gtk_button_new_with_label("Cancel");
    g_signal_connect(clear_btn, "clicked", G_CALLBACK(on_clear_pm), NULL);
    gtk_box_pack_end(GTK_BOX(app.recipient_bar), clear_btn, FALSE, FALSE, 6);
    gtk_widget_set_no_show_all(app.recipient_bar, TRUE);
    gtk_box_pack_start(GTK_BOX(chat_box), app.recipient_bar, FALSE, FALSE, 0);

    GtkWidget *chat_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(chat_scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    app.chat_buf = gtk_text_buffer_new(NULL);
    setup_text_tags();
    app.chat_view = gtk_text_view_new_with_buffer(app.chat_buf);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app.chat_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app.chat_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(app.chat_view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(app.chat_view), 16);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(app.chat_view), 16);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(app.chat_view), 12);
    gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(app.chat_view), 12);

    GtkTextIter end_iter;
    gtk_text_buffer_get_end_iter(app.chat_buf, &end_iter);
    app.end_mark = gtk_text_buffer_create_mark(app.chat_buf, "end", &end_iter, FALSE);
    gtk_container_add(GTK_CONTAINER(chat_scroll), app.chat_view);
    gtk_box_pack_start(GTK_BOX(chat_box), chat_scroll, TRUE, TRUE, 0);

    GtkWidget *input_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_style_context_add_class(gtk_widget_get_style_context(input_box), "msg-box");
    gtk_container_set_border_width(GTK_CONTAINER(input_box), 10);
    app.msg_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app.msg_entry),
                                   "Type a message...");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.msg_entry), "msg-entry");
    gtk_widget_set_sensitive(app.msg_entry, FALSE);
    g_signal_connect(app.msg_entry, "activate", G_CALLBACK(on_msg_activate), NULL);
    gtk_box_pack_start(GTK_BOX(input_box), app.msg_entry, TRUE, TRUE, 0);

    app.emoji_btn = gtk_button_new_with_label("\xf0\x9f\x98\x80");
    gtk_button_set_relief(GTK_BUTTON(app.emoji_btn), GTK_RELIEF_NONE);
    gtk_widget_set_sensitive(app.emoji_btn, FALSE);
    g_signal_connect(app.emoji_btn, "clicked", G_CALLBACK(on_emoji_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(input_box), app.emoji_btn, FALSE, FALSE, 0);

    app.send_btn = gtk_button_new_with_label("Send");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.send_btn), "send-btn");
    gtk_widget_set_sensitive(app.send_btn, FALSE);
    g_signal_connect(app.send_btn, "clicked", G_CALLBACK(on_send_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(input_box), app.send_btn, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(chat_box), input_box, FALSE, FALSE, 0);

    gtk_paned_pack2(GTK_PANED(paned), chat_box, TRUE, TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), paned, TRUE, TRUE, 0);

    app.status_label = gtk_label_new("  Disconnected");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.status_label), "statusbar");
    gtk_widget_set_halign(app.status_label, GTK_ALIGN_START);
    gtk_box_pack_end(GTK_BOX(vbox), app.status_label, FALSE, FALSE, 0);

    return vbox;
}
