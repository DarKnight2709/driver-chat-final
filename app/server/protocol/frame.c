#include "frame.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static int compute_frame_hmac(crypto_ctx_t *ctx,
                              const struct chat_frame *f,
                              uint8_t hmac_out[SHA256_DIGEST_SIZE])
{
    size_t buf_len = 1 + 2 + AES_IV_SIZE + f->payload_len;
    uint8_t *buf = malloc(buf_len);
    int ret;

    if (!buf) return -1;

    buf[0] = f->type;
    buf[1] = (f->payload_len >> 8) & 0xFF;
    buf[2] = f->payload_len & 0xFF;
    memcpy(buf + 3, f->iv, AES_IV_SIZE);
    memcpy(buf + 3 + AES_IV_SIZE, f->payload, f->payload_len);

    ret = crypto_sha256(ctx, buf, (uint32_t)buf_len, hmac_out);
    free(buf);
    return ret;
}

int send_frame_with_key(client_state_t *c, uint8_t type,
                        const void *payload, uint16_t plain_len,
                        const uint8_t *key)
{
    struct chat_frame f;
    uint32_t cipher_len = 0;
    int ret;

    memset(&f, 0, sizeof(f));
    f.version = PROTO_VERSION;
    f.type = type;

    crypto_random_bytes(f.iv, AES_IV_SIZE);

    ret = crypto_aes_encrypt(&c->crypto, key, f.iv,
                             (const uint8_t *)payload, plain_len,
                             f.payload, &cipher_len);
    if (ret < 0) return -1;

    f.payload_len = (uint16_t)cipher_len;
    if (compute_frame_hmac(&c->crypto, &f, f.hmac) < 0)
        return -1;

    size_t hdr_size = sizeof(f) - sizeof(f.payload);
    pthread_mutex_lock(&c->send_mutex);
    ssize_t sent = send(c->sock, &f, hdr_size + f.payload_len, MSG_NOSIGNAL);
    pthread_mutex_unlock(&c->send_mutex);
    if (sent < 0)
        return -1;

    return 0;
}

int send_frame(client_state_t *c, uint8_t type,
               const void *payload, uint16_t plain_len)
{
    return send_frame_with_key(c, type, payload, plain_len, c->session_key);
}

int recv_frame(client_state_t *c, struct chat_frame *f)
{
    size_t hdr_size = sizeof(*f) - sizeof(f->payload);
    ssize_t n;
    uint8_t expected_hmac[SHA256_DIGEST_SIZE];

    n = recv(c->sock, f, hdr_size, MSG_WAITALL);
    if (n <= 0) return -1;
    if ((size_t)n < hdr_size) return -1;

    if (f->version != PROTO_VERSION) return -1;
    if (f->payload_len > MAX_DATA_SIZE) return -1;

    if (f->payload_len > 0) {
        n = recv(c->sock, f->payload, f->payload_len, MSG_WAITALL);
        if (n != (ssize_t)f->payload_len) return -1;
    }

    if (compute_frame_hmac(&c->crypto, f, expected_hmac) < 0)
        return -1;

    if (memcmp(expected_hmac, f->hmac, SHA256_DIGEST_SIZE) != 0) {
        fprintf(stderr, "[server] HMAC mismatch from %s - dropping frame\n",
                c->username[0] ? c->username : "unknown");
        return -1;
    }

    return 0;
}
