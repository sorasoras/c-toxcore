/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */
#include "offline_msg.h"

#include <string.h>

#include "ccompat.h"
#include "net.h"

static uint16_t build_plaintext(uint64_t message_id, uint64_t sent_timestamp,
    Offline_Msg_Type type, const uint8_t *message, uint16_t message_length,
    uint8_t plaintext[OFFLINE_MSG_MAX_PLAINTEXT])
{
    uint8_t *ptr = plaintext;

    *ptr++ = OFFLINE_MSG_VERSION;               // 1
    net_pack_u64(ptr, message_id); ptr += 8;    // 8
    net_pack_u64(ptr, sent_timestamp); ptr += 8; // 8
    *ptr++ = (uint8_t)type;                     // 1
    net_pack_u16(ptr, message_length); ptr += 2; // 2
    memcpy(ptr, message, message_length);        // N
    ptr += message_length;

    return (uint16_t)(ptr - plaintext);
}

static bool parse_plaintext(const uint8_t *plaintext, uint16_t plaintext_length, Offline_Msg *msg)
{
    if (plaintext_length < OFFLINE_MSG_HEADER_SIZE) {
        return false;
    }
    const uint8_t *ptr = plaintext;

    if (*ptr++ != OFFLINE_MSG_VERSION) return false;

    net_unpack_u64(ptr, &msg->message_id); ptr += 8;
    net_unpack_u64(ptr, &msg->sent_timestamp); ptr += 8;
    msg->type = (Offline_Msg_Type)*ptr++;

    uint16_t msg_len;
    net_unpack_u16(ptr, &msg_len); ptr += 2;

    if (msg_len > OFFLINE_MSG_MAX_DATA_SIZE) return false;
    if (ptr + msg_len > plaintext + plaintext_length) return false;

    msg->data = ptr;
    msg->data_length = msg_len;
    return true;
}

bool offline_msg_create_envelope(
    const Memory *mem, const Random *rng, const Mono_Time *mono_time,
    const uint8_t sender_pubkey[CRYPTO_PUBLIC_KEY_SIZE],
    const uint8_t sender_seckey[CRYPTO_SECRET_KEY_SIZE],
    const uint8_t recipient_pubkey[CRYPTO_PUBLIC_KEY_SIZE],
    uint64_t message_id, Offline_Msg_Type type,
    const uint8_t *message, uint16_t message_length,
    uint8_t out[OFFLINE_MSG_MAX_ENVELOPE], uint16_t *out_length)
{
    if (mem == nullptr || rng == nullptr || mono_time == nullptr
            || sender_pubkey == nullptr || sender_seckey == nullptr
            || recipient_pubkey == nullptr || message == nullptr
            || out == nullptr || out_length == nullptr) {
        return false;
    }
    if (message_length > OFFLINE_MSG_MAX_DATA_SIZE) {
        return false;
    }

    // Build plaintext
    uint8_t plaintext[OFFLINE_MSG_MAX_PLAINTEXT];
    const uint64_t ts = mono_time_get(mono_time);
    const uint16_t pt_len = build_plaintext(message_id, ts, type, message, message_length, plaintext);

    // Generate nonce
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(rng, nonce);

    // Encrypt
    const int32_t ct_len = encrypt_data(mem, recipient_pubkey, sender_seckey,
        nonce, plaintext, pt_len, out + OFFLINE_MSG_OUTER_SIZE);
    if (ct_len == -1) return false;

    // Assemble envelope: sender_pk | nonce | ciphertext
    memcpy(out, sender_pubkey, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(out + CRYPTO_PUBLIC_KEY_SIZE, nonce, CRYPTO_NONCE_SIZE);
    *out_length = OFFLINE_MSG_OUTER_SIZE + (uint16_t)ct_len;
    return true;
}

bool offline_msg_open_envelope(
    const Memory *mem, const uint8_t recipient_seckey[CRYPTO_SECRET_KEY_SIZE],
    const uint8_t *envelope, uint16_t envelope_length, Offline_Msg *msg)
{
    if (mem == nullptr || recipient_seckey == nullptr
            || envelope == nullptr || msg == nullptr) {
        return false;
    }
    if (envelope_length < OFFLINE_MSG_OUTER_SIZE + CRYPTO_MAC_SIZE + OFFLINE_MSG_HEADER_SIZE) {
        return false;
    }

    // Extract sender_pk, nonce, ciphertext
    const uint8_t *sender_pk = envelope;
    const uint8_t *nonce = envelope + CRYPTO_PUBLIC_KEY_SIZE;
    const uint8_t *ciphertext = envelope + OFFLINE_MSG_OUTER_SIZE;
    const int32_t ct_len = envelope_length - OFFLINE_MSG_OUTER_SIZE;

    // Decrypt
    uint8_t plaintext[OFFLINE_MSG_MAX_PLAINTEXT];
    const int32_t pt_len = decrypt_data(mem, sender_pk, recipient_seckey,
        nonce, ciphertext, ct_len, plaintext);
    if (pt_len == -1) return false;

    // Parse
    if (!parse_plaintext(plaintext, (uint16_t)pt_len, msg)) return false;

    // Copy sender_pk from outer header
    memcpy(msg->sender_pubkey, sender_pk, CRYPTO_PUBLIC_KEY_SIZE);
    return true;
}

void offline_msg_pack_message_id(uint8_t dest[8], uint64_t message_id)
{
    net_pack_u64(dest, message_id);
}

uint64_t offline_msg_unpack_message_id(const uint8_t src[8])
{
    uint64_t id;
    net_unpack_u64(src, &id);
    return id;
}