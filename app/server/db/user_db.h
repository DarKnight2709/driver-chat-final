#ifndef USER_DB_H
#define USER_DB_H

#include <stdint.h>

#include "../../crypto_lib.h"

int user_db_init(const char *db_path);
void user_db_close(void);
int user_db_count_users(int *count_out);
int user_db_verify(const char *uname, const uint8_t *pwd_hash);
int user_db_add(const char *uname, const uint8_t *pwd_hash);
int user_db_update_password(const char *uname, const uint8_t *new_pwd_hash);
int user_db_add_plain(crypto_ctx_t *ctx, const char *uname, const char *pwd);

#endif
