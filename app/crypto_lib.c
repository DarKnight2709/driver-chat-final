/* =============================================================================
 * crypto_lib.c — Userspace implementation wrapping /dev/crypto_chat
 * =============================================================================
 */
#include "crypto_lib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/random.h>

/* ── Open driver ─────────────────────────────────────────── */
/*
 * crypto_open - mở thiết bị kernel crypto `/dev/crypto_chat` để gọi IOCTL.
 *
 * @ctx: con trỏ tới ngữ cảnh crypto (chứa fd; sẽ được ghi giá trị sau mở).
 *
 * Giá trị trả về:
 * - 0 khi mở thành công
 * - -1 khi open() thất bại.
 */
int crypto_open(crypto_ctx_t *ctx)
{
    ctx->fd = open(CRYPTO_CHAT_DEV_PATH, O_RDWR);
    if (ctx->fd < 0) {
        perror("crypto_open: open(" CRYPTO_CHAT_DEV_PATH ")");
        return -1;
    }
    return 0;
}

/*
 * crypto_close - đóng file descriptor của driver nếu đã mở.
 *
 * @ctx: ngữ cảnh crypto (fd sẽ được đóng và set lại -1).
 *
 * Giá trị trả về:
 * - void.
 */
void crypto_close(crypto_ctx_t *ctx)
{
    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
}

/* ── AES-256-CBC Encrypt ─────────────────────────────────── */
/*
 * crypto_aes_encrypt - mã hóa plaintext bằng AES-256-CBC thông qua driver.
 *
 * @ctx: ngữ cảnh chứa fd driver.
 * @key:  khóa AES-256 (32 bytes).
 * @iv:   IV AES-CBC (AES_IV_SIZE, thường 16 bytes).
 * @plain: plaintext input.
 * @plain_len: độ dài plaintext.
 * @cipher: buffer đầu ra để nhận ciphertext (đủ kích thước ciphertext).
 * @cipher_len: trả về độ dài ciphertext thực tế.
 *
 * Giá trị trả về:
 * - 0 khi thành công
 * - -1 khi ioctl thất bại.
 */
int crypto_aes_encrypt(crypto_ctx_t *ctx,
                       const uint8_t *key,    const uint8_t *iv,
                       const uint8_t *plain,  uint32_t plain_len,
                       uint8_t       *cipher, uint32_t *cipher_len)
{
    struct crypto_aes_req req;
    memset(&req, 0, sizeof(req));

    memcpy(req.key,   key, AES_KEY_SIZE);
    memcpy(req.iv,    iv,  AES_IV_SIZE);
    memcpy(req.input, plain, plain_len);
    req.input_len = plain_len;

    if (ioctl(ctx->fd, IOCTL_AES_ENCRYPT, &req) < 0) {
        perror("IOCTL_AES_ENCRYPT");
        return -1;
    }

    memcpy(cipher, req.output, req.output_len);
    *cipher_len = req.output_len;
    return 0;
}

/* ── AES-256-CBC Decrypt ─────────────────────────────────── */
/*
 * crypto_aes_decrypt - giải mã ciphertext bằng AES-256-CBC thông qua driver.
 *
 * @ctx: ngữ cảnh chứa fd driver.
 * @key:  khóa AES-256 (32 bytes).
 * @iv:   IV AES-CBC dùng tương ứng với ciphertext.
 * @cipher: ciphertext input.
 * @cipher_len: độ dài ciphertext.
 * @plain: buffer đầu ra để nhận plaintext.
 * @plain_len: trả về độ dài plaintext thực tế (sau khi driver loại PKCS#7 padding).
 *
 * Giá trị trả về:
 * - 0 khi thành công
 * - -1 khi ioctl thất bại.
 */
int crypto_aes_decrypt(crypto_ctx_t *ctx,
                       const uint8_t *key,   const uint8_t *iv,
                       const uint8_t *cipher, uint32_t cipher_len,
                       uint8_t       *plain,  uint32_t *plain_len)
{
    struct crypto_aes_req req;
    memset(&req, 0, sizeof(req));

    memcpy(req.key,   key, AES_KEY_SIZE);
    memcpy(req.iv,    iv,  AES_IV_SIZE);
    memcpy(req.input, cipher, cipher_len);
    req.input_len = cipher_len;

    if (ioctl(ctx->fd, IOCTL_AES_DECRYPT, &req) < 0) {
        perror("IOCTL_AES_DECRYPT");
        return -1;
    }

    memcpy(plain, req.output, req.output_len);
    *plain_len = req.output_len;
    return 0;
}

/* ── SHA-256 ─────────────────────────────────────────────── */
/*
 * crypto_sha256 - tính SHA-256 của một buffer dữ liệu qua driver.
 *
 * @ctx: ngữ cảnh chứa fd driver.
 * @data: dữ liệu input.
 * @data_len: độ dài dữ liệu.
 * @digest: buffer đích kích thước SHA256_DIGEST_SIZE bytes.
 *
 * Giá trị trả về:
 * - 0 khi thành công
 * - -1 khi ioctl thất bại.
 */
int crypto_sha256(crypto_ctx_t *ctx,
                  const uint8_t *data, uint32_t data_len,
                  uint8_t digest[SHA256_DIGEST_SIZE])
{
    struct crypto_hash_req req;
    memset(&req, 0, sizeof(req));

    memcpy(req.data, data, data_len);
    req.data_len = data_len;

    if (ioctl(ctx->fd, IOCTL_SHA256_HASH, &req) < 0) {
        perror("IOCTL_SHA256_HASH");
        return -1;
    }

    memcpy(digest, req.digest, SHA256_DIGEST_SIZE);
    return 0;
}

/* ── Key derivation ──────────────────────────────────────── */
/*
 * crypto_derive_key - dẫn xuất khóa AES từ password và salt thông qua IOCTL.
 *
 * Driver triển khai một dạng PBKDF2-like (lặp SHA-256) và xuất ra khóa 32 bytes.
 *
 * @ctx: ngữ cảnh chứa fd driver.
 * @password: chuỗi password.
 * @salt: salt 16 bytes.
 * @derived_key: buffer đầu ra (32 bytes AES_KEY_SIZE) chứa khóa dẫn xuất.
 *
 * Giá trị trả về:
 * - 0 khi thành công
 * - -1 khi ioctl thất bại.
 */
int crypto_derive_key(crypto_ctx_t *ctx,
                      const char   *password,
                      const uint8_t salt[16],
                      uint8_t       derived_key[AES_KEY_SIZE])
{
    struct crypto_kdf_req req;
    memset(&req, 0, sizeof(req));

    req.password_len = (uint32_t)strlen(password);
    if (req.password_len > MAX_PASSWORD_LEN)
        req.password_len = MAX_PASSWORD_LEN;

    memcpy(req.password, password, req.password_len);
    memcpy(req.salt,     salt,     16);

    if (ioctl(ctx->fd, IOCTL_DERIVE_KEY, &req) < 0) {
        perror("IOCTL_DERIVE_KEY");
        return -1;
    }

    memcpy(derived_key, req.derived_key, AES_KEY_SIZE);
    return 0;
}

/* ── Secure random bytes (getrandom syscall) ─────────────── */
/*
 * crypto_random_bytes - sinh dữ liệu ngẫu nhiên an toàn để làm IV/salt.
 *
 * @buf: buffer nhận bytes ngẫu nhiên.
 * @len: số byte cần sinh.
 *
 * Cách làm:
 * - ưu tiên syscall `getrandom`
 * - nếu thất bại: fallback sang đọc `/dev/urandom`
 *
 * Giá trị trả về:
 * - void.
 */
void crypto_random_bytes(uint8_t *buf, size_t len)
{
    ssize_t ret = getrandom(buf, len, 0);
    if (ret < 0 || (size_t)ret != len) {
        /* Fallback to /dev/urandom */
        FILE *f = fopen("/dev/urandom", "rb");
        if (f) { fread(buf, 1, len, f); fclose(f); }
    }
}

/* ── Hex dump (debug) ────────────────────────────────────── */
/*
 * crypto_hex_dump - in ra hexdump dạng debug cho một buffer.
 *
 * @label: nhãn đi kèm.
 * @data: dữ liệu cần in.
 * @len: độ dài dữ liệu.
 *
 * Ghi chú:
 * - chỉ in tối đa 64 bytes để tránh spam log.
 *
 * Giá trị trả về:
 * - void.
 */
void crypto_hex_dump(const char *label, const uint8_t *data, size_t len)
{
    printf("[%s] (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 64; i++)
        printf("%02x", data[i]);
    if (len > 64) printf("...");
    printf("\n");
}
