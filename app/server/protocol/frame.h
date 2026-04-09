#ifndef PROTOCOL_FRAME_H
#define PROTOCOL_FRAME_H

#include <stdint.h>

#include "../core/server_state.h"

int send_frame_with_key(client_state_t *c, uint8_t type,
                        const void *payload, uint16_t plain_len,
                        const uint8_t *key);
int send_frame(client_state_t *c, uint8_t type,
               const void *payload, uint16_t plain_len);
int recv_frame(client_state_t *c, struct chat_frame *f);

#endif
