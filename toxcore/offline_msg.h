/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

/**
 * @brief Offline message envelope encryption and serialization.
 *
 * Wire format (stored in DHT):
 *   [32 bytes]     sender_public_key (unencrypted — needed for crypto_box_open)
 *   [24 bytes]     crypto_box nonce (random)
 *   [N+16 bytes]   crypto_box ciphertext (plaintext + MAC)
 *
 * Plaintext format (inside crypto_box):
 *   [1 byte]       version (0x01)
 *   [8 bytes]      message_id (big-endian)
 *   [8 bytes]      sent_timestamp (ms, big-endian)
 *   [1 byte]       message_type (0=normal, 1=action)
 *   [2 bytes]      message_length (network byte order)
 *   [N bytes]      message_data
 */
#ifndef C_TOXCORE_TOXCORE_OFFLINE_MSG_H
#define C_TOXCORE_TOXCORE_OFFLINE_MSG_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"
#include "crypto_core.h"
#include "mem.h"
#include "mono_time.h"
#include "rng.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OFFLINE_MSG_VERSION         1
#define OFFLINE_MSG_MAX_DATA_SIZE   2048
#define OFFLINE_MSG_HEADER_SIZE     (1 + 8 + 8 + 1 + 2)
#define OFFLINE_MSG_OUTER_SIZE      (CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE)
#define OFFLINE_MSG_MAX_PLAINTEXT   (OFFLINE_MSG_HEADER_SIZE + OFFLINE_MSG_MAX_DATA_SIZE)
#define OFFLINE_MSG_MAX_ENVELOPE    (OFFLINE_MSG_OUTER_SIZE + OFFLINE_MSG_MAX_PLAINTEXT + CRYPTO_MAC_SIZE)

typedef enum Offline_Msg_Type {
    OFFLINE_MSG_TYPE_NORMAL = 0,
    OFFLINE_MSG_TYPE_ACTION = 1,
} Offline_Msg_Type;

typedef struct Offline_Msg {
    uint8_t sender_pubkey[CRYPTO_PUBLIC_KEY_SIZE];
    uint64_t message_id;
    uint64_t sent_timestamp;
    Offline_Msg_Type type;
    const uint8_t *_Nullable data;
    uint16_t data_length;
} Offline_Msg;

bool offline_msg_create_envelope(
    const Memory *_Nonnull mem, const Random *_Nonnull rng,
    const Mono_Time *_Nonnull mono_time,
    const uint8_t sender_pubkey[CRYPTO_PUBLIC_KEY_SIZE],
    const uint8_t sender_seckey[CRYPTO_SECRET_KEY_SIZE],
    const uint8_t recipient_pubkey[CRYPTO_PUBLIC_KEY_SIZE],
    uint64_t message_id, Offline_Msg_Type type,
    const uint8_t *_Nonnull message, uint16_t message_length,
    uint8_t out[OFFLINE_MSG_MAX_ENVELOPE],
    uint16_t *_Nonnull out_length);

bool offline_msg_open_envelope(
    const Memory *_Nonnull mem,
    const uint8_t recipient_seckey[CRYPTO_SECRET_KEY_SIZE],
    const uint8_t *_Nonnull envelope, uint16_t envelope_length,
    Offline_Msg *_Nonnull msg);

void offline_msg_pack_message_id(uint8_t dest[8], uint64_t message_id);
uint64_t offline_msg_unpack_message_id(const uint8_t src[8]);

#ifdef __cplusplus
}
#endif
#endif