#include "user_db.h"

#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include <pthread.h>

static sqlite3 *g_user_db = NULL;
static pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

int user_db_init(const char *db_path)
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

void user_db_close(void)
{
    pthread_mutex_lock(&db_mutex);
    if (g_user_db) {
        sqlite3_close(g_user_db);
        g_user_db = NULL;
    }
    pthread_mutex_unlock(&db_mutex);
}

int user_db_count_users(int *count_out)
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

int user_db_verify(const char *uname, const uint8_t *pwd_hash)
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

int user_db_add(const char *uname, const uint8_t *pwd_hash)
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

int user_db_update_password(const char *uname,
                            const uint8_t *new_pwd_hash)
{
    sqlite3_stmt *stmt = NULL;
    int rc;

    if (!uname || !new_pwd_hash) return -1;

    pthread_mutex_lock(&db_mutex);
    if (!g_user_db) {
        pthread_mutex_unlock(&db_mutex);
        return -1;
    }

    rc = sqlite3_prepare_v2(g_user_db,
                            "UPDATE users SET password_hash = ?1 "
                            "WHERE username = ?2;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&db_mutex);
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, new_pwd_hash, SHA256_DIGEST_SIZE,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, uname, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&db_mutex);
        return -1;
    }

    if (sqlite3_changes(g_user_db) <= 0) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&db_mutex);
        return -1;
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_mutex);
    return 0;
}

int user_db_add_plain(crypto_ctx_t *ctx, const char *uname, const char *pwd)
{
    uint8_t hash[SHA256_DIGEST_SIZE];
    if (crypto_sha256(ctx, (const uint8_t *)pwd, (uint32_t)strlen(pwd), hash) < 0)
        return -1;
    return user_db_add(uname, hash);
}
