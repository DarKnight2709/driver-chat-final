/* =============================================================================
 * crypto_lib.h — Userspace wrapper for /dev/crypto_chat IOCTL API
 * =============================================================================
 */
#ifndef CRYPTO_LIB_H
#define CRYPTO_LIB_H

#include <stdint.h>
#include <stddef.h>
#include "../driver/crypto_chat.h"

/* ── Driver handle ───────────────────────────────────────── */
typedef struct {
    int fd;   /* file descriptor for /dev/crypto_chat */
} crypto_ctx_t;

/* Open / close the driver */
int  crypto_open (crypto_ctx_t *ctx);
void crypto_close(crypto_ctx_t *ctx);

/* ── AES-256-CBC ─────────────────────────────────────────── */
int crypto_aes_encrypt(crypto_ctx_t *ctx,
                       const uint8_t *key,     /* 32 bytes */
                       const uint8_t *iv,      /* 16 bytes */
                       const uint8_t *plain,   uint32_t plain_len,
                       uint8_t       *cipher,  uint32_t *cipher_len);

int crypto_aes_decrypt(crypto_ctx_t *ctx,
                       const uint8_t *key,
                       const uint8_t *iv,
                       const uint8_t *cipher,  uint32_t cipher_len,
                       uint8_t       *plain,   uint32_t *plain_len);

/* ── SHA-256 ─────────────────────────────────────────────── */
int crypto_sha256(crypto_ctx_t *ctx,
                  const uint8_t *data, uint32_t data_len,
                  uint8_t       digest[SHA256_DIGEST_SIZE]);

/* ── Key derivation (password → AES-256 key) ─────────────── */
int crypto_derive_key(crypto_ctx_t *ctx,
                      const char   *password,
                      const uint8_t salt[16],
                      uint8_t       derived_key[AES_KEY_SIZE]);

/* ── Utility ─────────────────────────────────────────────── */
void crypto_random_bytes(uint8_t *buf, size_t len);
void crypto_hex_dump(const char *label,
                     const uint8_t *data, size_t len);

#endif /* CRYPTO_LIB_H */
