/* =============================================================================
 * history.c — Server host/port history management (auto-complete & persistence)
 * ============================================================================= */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/app_state.h"

/* ── Internal helpers ────────────────────────────────────── */

static char *get_server_history_path(const char *filename)
{
    return g_build_filename(g_get_user_config_dir(), "cryptochat",
                            filename, NULL);
}

static guint list_store_count(GtkListStore *store)
{
    GtkTreeIter iter;
    guint count = 0;

    if (!gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter))
        return 0;

    do {
        count++;
    } while (gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter));

    return count;
}

static gboolean list_store_has_value(GtkListStore *store, const char *value)
{
    GtkTreeIter iter;
    gboolean valid;

    if (!value || !*value)
        return TRUE;

    valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);
    while (valid) {
        char *current = NULL;

        gtk_tree_model_get(GTK_TREE_MODEL(store), &iter, 0, &current, -1);
        if (g_strcmp0(current, value) == 0) {
            g_free(current);
            return TRUE;
        }
        g_free(current);
        valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
    }

    return FALSE;
}

static void list_store_trim(GtkListStore *store, guint limit)
{
    while (list_store_count(store) > limit) {
        GtkTreeIter iter;
        guint last_index = list_store_count(store) - 1;

        if (gtk_tree_model_iter_nth_child(GTK_TREE_MODEL(store), &iter,
                                          NULL, last_index))
            gtk_list_store_remove(store, &iter);
        else
            gtk_list_store_clear(store);
    }
}

static void list_store_prepend_unique(GtkListStore *store, const char *value,
                                      guint limit)
{
    GtkTreeIter iter;
    gboolean valid;

    if (!value || !*value)
        return;

    valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);
    while (valid) {
        char *current = NULL;

        gtk_tree_model_get(GTK_TREE_MODEL(store), &iter, 0, &current, -1);
        if (g_strcmp0(current, value) == 0) {
            g_free(current);
            gtk_list_store_remove(store, &iter);
            break;
        }
        g_free(current);
        valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
    }

    gtk_list_store_prepend(store, &iter);
    gtk_list_store_set(store, &iter, 0, value, -1);
    list_store_trim(store, limit);
}

static void list_store_append_unique(GtkListStore *store, const char *value,
                                    guint limit)
{
    GtkTreeIter iter;

    if (!value || !*value)
        return;
    if (list_store_has_value(store, value))
        return;
    if (list_store_count(store) >= limit)
        return;

    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter, 0, value, -1);
}

static void load_history_file(GtkListStore *store, const char *path)
{
    FILE *fp = fopen(path, "r");
    char line[256];

    if (!fp)
        return;

    while (fgets(line, sizeof(line), fp)) {
        g_strchomp(line);
        g_strstrip(line);
        list_store_append_unique(store, line, SERVER_HISTORY_LIMIT);
    }

    fclose(fp);
}

static void save_history_file(GtkListStore *store, const char *path)
{
    FILE *fp;
    GtkTreeIter iter;
    gboolean valid;
    char *dir = g_path_get_dirname(path);

    if (!dir) return;
    g_mkdir_with_parents(dir, 0700);
    g_free(dir);

    fp = fopen(path, "w");
    if (!fp)
        return;

    valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);
    while (valid) {
        char *value = NULL;
        gtk_tree_model_get(GTK_TREE_MODEL(store), &iter, 0, &value, -1);
        if (value && *value)
            fprintf(fp, "%s\n", value);
        g_free(value);
        valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
    }

    fclose(fp);
}

static void init_history_completion(GtkWidget *entry, GtkListStore **store_slot,
                                    const char *history_file)
{
    GtkEntryCompletion *completion;

    if (!*store_slot)
        *store_slot = gtk_list_store_new(1, G_TYPE_STRING);

    load_history_file(*store_slot, history_file);

    completion = gtk_entry_completion_new();
    gtk_entry_completion_set_model(completion, GTK_TREE_MODEL(*store_slot));
    gtk_entry_completion_set_text_column(completion, 0);
    gtk_entry_completion_set_minimum_key_length(completion, 1);
    gtk_entry_completion_set_popup_completion(completion, TRUE);
    gtk_entry_set_completion(GTK_ENTRY(entry), completion);
    g_object_unref(completion);
}

static void history_promote_value(GtkListStore *store, const char *value,
                                  const char *history_file)
{
    list_store_prepend_unique(store, value, SERVER_HISTORY_LIMIT);
    save_history_file(store, history_file);
}

static gboolean ui_remember_server_history(gpointer data)
{
    ServerHistoryArgs *args = data;
    char *host_path = get_server_history_path("server_hosts.txt");
    char *port_path = get_server_history_path("server_ports.txt");

    history_promote_value(app.host_history_store, args->host, host_path);

    {
        char port_text[32];
        snprintf(port_text, sizeof(port_text), "%d", args->port);
        history_promote_value(app.port_history_store, port_text, port_path);
    }

    g_free(host_path);
    g_free(port_path);
    g_free(args);
    return G_SOURCE_REMOVE;
}


/* ── Public API ──────────────────────────────────────────── */

void queue_server_history(const char *host, int port)
{
    ServerHistoryArgs *args = g_new0(ServerHistoryArgs, 1);
    snprintf(args->host, sizeof(args->host), "%s",
             host && *host ? host : DEFAULT_HOST);
    args->port = port > 0 ? port : atoi(DEFAULT_PORT);
    g_idle_add(ui_remember_server_history, args);
}

void load_server_history(void)
{
    char *host_path;
    char *port_path;

    if (app.host_entry) {
        host_path = get_server_history_path("server_hosts.txt");
        init_history_completion(app.host_entry, &app.host_history_store,
                                host_path);
        g_free(host_path);
    }
    if (app.port_entry) {
        port_path = get_server_history_path("server_ports.txt");
        init_history_completion(app.port_entry, &app.port_history_store,
                                port_path);
        g_free(port_path);
    }
}

void apply_startup_server_defaults(int argc, char *argv[])
{
    const char *host = NULL;
    const char *port = NULL;
    char *host_copy = NULL;
    char *port_copy = NULL;

    if (argc >= 2)
        host = argv[1];
    if (argc >= 3)
        port = argv[2];

    if (!host && app.host_history_store) {
        GtkTreeIter iter;
        if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(app.host_history_store), &iter)) {
            gtk_tree_model_get(GTK_TREE_MODEL(app.host_history_store), &iter, 0, &host_copy, -1);
            host = host_copy;
        }
    }

    if (!port && app.port_history_store) {
        GtkTreeIter iter;
        if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(app.port_history_store), &iter)) {
            gtk_tree_model_get(GTK_TREE_MODEL(app.port_history_store), &iter, 0, &port_copy, -1);
            port = port_copy;
        }
    }

    gtk_entry_set_text(GTK_ENTRY(app.host_entry), host ? host : DEFAULT_HOST);
    gtk_entry_set_text(GTK_ENTRY(app.port_entry), port ? port : DEFAULT_PORT);

    g_free(host_copy);
    g_free(port_copy);
}
