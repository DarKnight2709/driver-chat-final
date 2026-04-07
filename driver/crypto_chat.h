/* =============================================================================
 * crypto_chat.h - Shared header: Kernel Driver + Userspace
 *
 * CentOS 7/8 x86_64 | USB NIC support | AES-256-CBC + SHA-256
 * =============================================================================
 */
#ifndef CRYPTO_CHAT_H
#define CRYPTO_CHAT_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <linux/types.h>
#include <linux/ioctl.h>
#endif

/* ── Device node ─────────────────────────────────────────── */
#define CRYPTO_CHAT_DEV_NAME   "crypto_chat"
#define CRYPTO_CHAT_DEV_PATH   "/dev/crypto_chat"
#define CRYPTO_CHAT_CLASS_NAME "crypto_chat_class"

/* ── Crypto constants ────────────────────────────────────── */
#define AES_KEY_SIZE       32   /* AES-256                   */
#define AES_IV_SIZE        16   /* 128-bit IV                */
#define AES_BLOCK_SIZE_VAL 16   /* AES block = 16 bytes      */
#define SHA256_DIGEST_SIZE 32   /* SHA-256 output = 32 bytes */
#define MAX_DATA_SIZE    4096   /* max plaintext / cipher    */
#define MAX_USERNAME_LEN   64
#define MAX_PASSWORD_LEN   64
#define MAX_MSG_LEN      1024

/* ── IOCTL magic number ──────────────────────────────────── */
#define CRYPTO_IOC_MAGIC  'K'

/* ── Request structures (shared kernel/userspace) ────────── */

/* AES encrypt / decrypt */
struct crypto_aes_req {
    __u8  key[AES_KEY_SIZE];     /* 256-bit key              */
    __u8  iv[AES_IV_SIZE];       /* 128-bit IV (CBC)         */
    __u8  input[MAX_DATA_SIZE];  /* plaintext or ciphertext  */
    __u32 input_len;             /* bytes in input[]         */
    __u8  output[MAX_DATA_SIZE]; /* ciphertext or plaintext  */
    __u32 output_len;            /* bytes written to output  */
};

/* SHA-256 hash */
struct crypto_hash_req {
    __u8  data[MAX_DATA_SIZE];
    __u32 data_len;
    __u8  digest[SHA256_DIGEST_SIZE];  /* 32-byte result     */
};

/* Key derivation from password */
struct crypto_kdf_req {
    __u8  password[MAX_PASSWORD_LEN];
    __u32 password_len;
    __u8  salt[16];
    __u8  derived_key[AES_KEY_SIZE];   /* out: 32-byte key   */
};

/* ── IOCTL commands ──────────────────────────────────────── */
#define IOCTL_AES_ENCRYPT  _IOWR(CRYPTO_IOC_MAGIC, 1, struct crypto_aes_req)
#define IOCTL_AES_DECRYPT  _IOWR(CRYPTO_IOC_MAGIC, 2, struct crypto_aes_req)
#define IOCTL_SHA256_HASH  _IOWR(CRYPTO_IOC_MAGIC, 3, struct crypto_hash_req)
#define IOCTL_DERIVE_KEY   _IOWR(CRYPTO_IOC_MAGIC, 4, struct crypto_kdf_req)
#define IOCTL_GET_VERSION  _IOR (CRYPTO_IOC_MAGIC, 5, __u32)

/* ── Network protocol (chat messages over TCP) ───────────── */
#define PROTO_VERSION      1
#define MSG_TYPE_AUTH      0x01   /* login request            */
#define MSG_TYPE_AUTH_OK   0x02   /* login accepted           */
#define MSG_TYPE_AUTH_FAIL 0x03   /* login rejected           */
#define MSG_TYPE_CHAT      0x04   /* encrypted chat message   */
#define MSG_TYPE_SYSTEM    0x05   /* server notice (plain)    */
#define MSG_TYPE_LOGOUT    0x06   /* graceful disconnect      */
#define MSG_TYPE_LIST      0x07   /* list online users        */
#define MSG_TYPE_BROADCAST 0x08   /* broadcast to all         */
#define MSG_TYPE_REGISTER  0x09   /* register new user        */
#define MSG_TYPE_REG_OK    0x0A   /* registration success     */
#define MSG_TYPE_REG_FAIL  0x0B   /* registration failed      */

/* Fixed-size wire frame (simplifies framing) */
struct chat_frame {
    __u8  version;                      /* PROTO_VERSION             */
    __u8  type;                         /* MSG_TYPE_*                */
    __u16 payload_len;                  /* bytes of payload[]        */
    __u8  iv[AES_IV_SIZE];              /* IV used to encrypt payload*/
    __u8  hmac[SHA256_DIGEST_SIZE];     /* SHA256(type|iv|payload)   */
    __u8  payload[MAX_DATA_SIZE];       /* encrypted data            */
} __attribute__((packed));

/* Auth payload (inside chat_frame.payload, AES-encrypted) */
struct auth_payload {
    char username[MAX_USERNAME_LEN];
    __u8 password_hash[SHA256_DIGEST_SIZE]; /* SHA256(password)      */
} __attribute__((packed));

/* Chat payload */
struct chat_payload {
    char sender[MAX_USERNAME_LEN];
    char recipient[MAX_USERNAME_LEN];   /* empty = broadcast         */
    char message[MAX_MSG_LEN];
    __u64 timestamp;
} __attribute__((packed));

#endif /* CRYPTO_CHAT_H */
