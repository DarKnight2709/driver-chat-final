/* =============================================================================
 * main.c — GUI Client entry point, CSS theme, and App state definition
 * ============================================================================= */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "../include/app_state.h"

/* ── Global application state (singleton) ────────────────── */
App app;

/* ── CSS Theme ───────────────────────────────────────────── */
static const char *APP_CSS =
    "window { background-color: #0e1120; }\n"

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

    ".login-card {\n"
    "  background-color: #1c2236;\n"
    "  border-radius: 14px;\n"
    "  border: 1px solid #2e3855;\n"
    "  padding: 36px;\n"
    "}\n"
    ".login-subtitle { color: #7a86aa; font-size: 13px; }\n"

    ".field-label {\n"
    "  color: #9aa8c8;\n"
    "  font-size: 12px;\n"
    "  font-weight: bold;\n"
    "}\n"

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

    "textview { font-size: 14px; font-family: monospace; }\n"
    "textview text {\n"
    "  background-color: #0e1120;\n"
    "  color: #dde3f5;\n"
    "}\n"

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

    ".statusbar {\n"
    "  background-color: #0a0e1a;\n"
    "  color: #4e5a7a;\n"
    "  padding: 5px 14px;\n"
    "  font-size: 12px;\n"
    "  border-top: 1px solid #2e3855;\n"
    "}\n"

    ".pm-bar {\n"
    "  background-color: #1a2240;\n"
    "  border-bottom: 1px solid #3d4e7a;\n"
    "  padding: 7px 12px;\n"
    "}\n"
    ".pm-bar label {\n"
    "  color: #6fa3f7;\n"
    "  font-size: 12px;\n"
    "  font-weight: bold;\n"
    "}\n"
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

    ".error-status { color: #f47067; }\n"
    ".success-status { color: #4ec97e; }\n"

    "separator { background-color: #2e3855; min-height: 1px; min-width: 1px; }\n"
;

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

int main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);

    memset(&app, 0, sizeof(app));
    app.sock      = -1;
    app.crypto.fd = -1;
    app.messages  = g_ptr_array_new();

    gtk_init(&argc, &argv);
    setup_css();

    app.header_bar = gtk_header_bar_new();
    gtk_header_bar_set_title(GTK_HEADER_BAR(app.header_bar), "CryptoChat");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(app.header_bar),
                                "Secure Chat Application");
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(app.header_bar), TRUE);

    app.change_pass_btn = gtk_button_new_with_label("Change Password");
    gtk_widget_set_sensitive(app.change_pass_btn, FALSE);
    gtk_widget_set_no_show_all(app.change_pass_btn, TRUE);
    gtk_widget_hide(app.change_pass_btn);
    g_signal_connect(app.change_pass_btn, "clicked",
                     G_CALLBACK(on_change_password_clicked), NULL);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(app.header_bar), app.change_pass_btn);

    app.logout_btn = gtk_button_new_with_label("Logout");
    gtk_widget_set_sensitive(app.logout_btn, FALSE);
    gtk_widget_set_no_show_all(app.logout_btn, TRUE);
    gtk_widget_hide(app.logout_btn);
    g_signal_connect(app.logout_btn, "clicked",
                     G_CALLBACK(on_logout_clicked), NULL);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(app.header_bar), app.logout_btn);

    app.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_titlebar(GTK_WINDOW(app.window), app.header_bar);
    gtk_window_set_default_size(GTK_WINDOW(app.window), 980, 660);
    gtk_window_set_position(GTK_WINDOW(app.window), GTK_WIN_POS_CENTER);
    g_signal_connect(app.window, "destroy",
                     G_CALLBACK(on_window_destroy), NULL);

    app.stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(app.stack),
                                  GTK_STACK_TRANSITION_TYPE_SLIDE_LEFT);
    gtk_stack_set_transition_duration(GTK_STACK(app.stack), 300);

    gtk_stack_add_named(GTK_STACK(app.stack), build_login_page(), "login");
    gtk_stack_add_named(GTK_STACK(app.stack), build_chat_page(),  "chat");
    gtk_container_add(GTK_CONTAINER(app.window), app.stack);

    apply_startup_server_defaults(argc, argv);

    app.list_timer_id = g_timeout_add_seconds(LIST_INTERVAL_SEC,
                                               on_list_timer, NULL);

    gtk_widget_show_all(app.window);
    gtk_stack_set_visible_child_name(GTK_STACK(app.stack), "login");

    gtk_main();
    return 0;
}
