/* =============================================================================
 * test_crypto.c — Driver smoke-test
 * Verifies AES-256-CBC and SHA-256 IOCTLs
 * =============================================================================
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "crypto_lib.h"

static int passed = 0, failed = 0;

#define PASS(msg) do { printf("  [PASS] %s\n", msg); passed++; } while(0)
#define FAIL(msg) do { printf("  [FAIL] %s\n", msg); failed++; } while(0)

static void test_sha256(crypto_ctx_t *ctx)
{
    printf("\n── SHA-256 Tests ──\n");
    /* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    const char *empty = "";
    const uint8_t expected_empty[32] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
        0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
        0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    };

    uint8_t digest[SHA256_DIGEST_SIZE];
    int ret = crypto_sha256(ctx, (const uint8_t *)empty, 0, digest);

    if (ret < 0) { FAIL("SHA-256 IOCTL error"); return; }
    if (memcmp(digest, expected_empty, 32) == 0)
        PASS("SHA-256(\"\") == known vector");
    else
        FAIL("SHA-256(\"\") mismatch");

    /* Test "abc" */
    const uint8_t expected_abc[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    ret = crypto_sha256(ctx, (const uint8_t *)"abc", 3, digest);
    if (ret < 0) { FAIL("SHA-256(abc) IOCTL error"); return; }
    if (memcmp(digest, expected_abc, 32) == 0)
        PASS("SHA-256(\"abc\") == known vector");
    else
        FAIL("SHA-256(\"abc\") mismatch");
}

static void test_aes(crypto_ctx_t *ctx)
{
    printf("\n── AES-256-CBC Tests ──\n");

    uint8_t key[AES_KEY_SIZE];
    uint8_t iv[AES_IV_SIZE];
    memset(key, 0x42, AES_KEY_SIZE);
    memset(iv,  0x00, AES_IV_SIZE);

    const char *plaintext = "Hello CryptoChat! AES-256-CBC test.";
    uint32_t plain_len = (uint32_t)strlen(plaintext);

    uint8_t cipher[MAX_DATA_SIZE];
    uint8_t recovered[MAX_DATA_SIZE + 1];
    uint32_t cipher_len = 0, recovered_len = 0;

    /* Encrypt */
    int ret = crypto_aes_encrypt(ctx, key, iv,
                                 (const uint8_t *)plaintext, plain_len,
                                 cipher, &cipher_len);
    if (ret < 0) { FAIL("AES encrypt IOCTL error"); return; }
    if (cipher_len >= plain_len)
        PASS("AES encrypt produced output");
    else
        FAIL("AES encrypt: unexpected output length");

    /* Decrypt */
    ret = crypto_aes_decrypt(ctx, key, iv,
                              cipher, cipher_len,
                              recovered, &recovered_len);
    if (ret < 0) { FAIL("AES decrypt IOCTL error"); return; }

    recovered[recovered_len] = '\0';
    if (recovered_len == plain_len &&
        memcmp(recovered, plaintext, plain_len) == 0)
        PASS("AES decrypt(encrypt(x)) == x");
    else
        FAIL("AES round-trip mismatch");

    /* Different IV should produce different ciphertext */
    uint8_t iv2[AES_IV_SIZE];
    uint8_t cipher2[MAX_DATA_SIZE];
    uint32_t cipher2_len = 0;
    memset(iv2, 0xFF, AES_IV_SIZE);

    crypto_aes_encrypt(ctx, key, iv2,
                       (const uint8_t *)plaintext, plain_len,
                       cipher2, &cipher2_len);
    if (memcmp(cipher, cipher2, cipher_len) != 0)
        PASS("Different IVs → different ciphertexts");
    else
        FAIL("Same ciphertext with different IVs (IV not used?)");
}

static void test_key_derivation(crypto_ctx_t *ctx)
{
    printf("\n── Key Derivation Tests ──\n");

    uint8_t salt[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
    uint8_t key1[AES_KEY_SIZE], key2[AES_KEY_SIZE];

    int r1 = crypto_derive_key(ctx, "password", salt, key1);
    int r2 = crypto_derive_key(ctx, "password", salt, key2);

    if (r1 < 0 || r2 < 0) { FAIL("Key derivation IOCTL error"); return; }

    if (memcmp(key1, key2, AES_KEY_SIZE) == 0)
        PASS("Same password + salt → same key (deterministic)");
    else
        FAIL("Same password + salt → different keys (non-deterministic!)");

    uint8_t key3[AES_KEY_SIZE];
    crypto_derive_key(ctx, "different_password", salt, key3);
    if (memcmp(key1, key3, AES_KEY_SIZE) != 0)
        PASS("Different passwords → different keys");
    else
        FAIL("Different passwords → same key (collision!)");
}

int main(void)
{
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  CryptoChat Kernel Driver — Smoke Test   ║\n");
    printf("╚══════════════════════════════════════════╝\n");

    crypto_ctx_t ctx;
    if (crypto_open(&ctx) < 0) {
        fprintf(stderr, "Cannot open driver. Run: make -C ../driver install\n");
        return 1;
    }

    /* Just do a basic open/close to check driver version via compile check */
    printf("\nDriver opened: %s\n", CRYPTO_CHAT_DEV_PATH);

    test_sha256(&ctx);
    test_aes(&ctx);
    test_key_derivation(&ctx);

    crypto_close(&ctx);

    printf("\n══════════════════════════\n");
    printf("Results: %d passed, %d failed\n", passed, failed);
    printf("══════════════════════════\n");

    return failed > 0 ? 1 : 0;
}
