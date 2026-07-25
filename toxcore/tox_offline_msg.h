/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

/**
 * @brief Offline messaging API for Tox.
 *
 * This header defines the public API for sending and receiving messages
 * that are stored in the DHT when the recipient is offline. Applications
 * include this in addition to tox.h.
 *
 * ## Usage
 *
 * Sending (always works, even if friend is offline):
 *   tox_friend_send_offline_message(tox, friend_num, TOX_MESSAGE_TYPE_NORMAL,
 *       message, length, &message_id, &error);
 *
 * Receiving (callback fires for each stored message retrieved):
 *   tox_callback_friend_offline_message(tox, my_callback);
 *   // Messages are delivered automatically in tox_iterate(),
 *   // or manually via tox_friend_query_offline_messages(tox).
 */
#ifndef C_TOXCORE_TOXCORE_TOX_OFFLINE_MSG_H
#define C_TOXCORE_TOXCORE_TOX_OFFLINE_MSG_H

#include "tox.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Error codes for tox_friend_send_offline_message.
 */
typedef enum Tox_Err_Friend_Send_Offline_Message {
    TOX_ERR_FRIEND_SEND_OFFLINE_MESSAGE_OK,
    TOX_ERR_FRIEND_SEND_OFFLINE_MESSAGE_FRIEND_NOT_FOUND,
    TOX_ERR_FRIEND_SEND_OFFLINE_MESSAGE_TOO_LONG,
    TOX_ERR_FRIEND_SEND_OFFLINE_MESSAGE_STORE_FAILED,
    TOX_ERR_FRIEND_SEND_OFFLINE_MESSAGE_NULL,
} Tox_Err_Friend_Send_Offline_Message;

/**
 * @brief Send a message to a friend that will be stored in the DHT if the
 * friend is offline.
 *
 * If the friend is currently online and connected, the message is delivered
 * directly (same as tox_friend_send_message). If the friend is offline, the
 * message is encrypted and stored in the DHT under the friend's public key.
 * When the friend comes online, it is delivered via the
 * tox_friend_offline_message_cb callback.
 *
 * @param message_id On success, set to a unique identifier for this message.
 * @return true on success.
 */
bool tox_friend_send_offline_message(
    Tox *tox, uint32_t friend_number,
    Tox_Message_Type type, const uint8_t *message, size_t length,
    uint64_t *message_id,
    Tox_Err_Friend_Send_Offline_Message *error);

/**
 * @brief Callback for receiving offline messages.
 *
 * @param friend_number The friend who sent the message.
 * @param message_id Unique message identifier (for deduplication).
 * @param sent_timestamp Unix timestamp in milliseconds when the message was sent.
 */
typedef void tox_friend_offline_message_cb(
    Tox *tox, uint32_t friend_number, uint64_t message_id,
    uint64_t sent_timestamp, Tox_Message_Type type,
    const uint8_t *message, size_t length, void *user_data);

/**
 * @brief Set the callback for offline message reception.
 */
void tox_callback_friend_offline_message(
    Tox *tox, tox_friend_offline_message_cb *callback);

/**
 * @brief Manually trigger a poll for offline messages.
 *
 * Normally offline message polling happens automatically during tox_iterate(),
 * but this allows the application to request an immediate check for pending
 * messages from the DHT.
 */
void tox_friend_query_offline_messages(Tox *tox);

/**
 * @brief Enable or disable offline messaging for this Tox instance.
 *
 * When disabled (default), this instance acts only as a client — it can
 * send and receive its own offline messages but does not store messages
 * for other peers in the DHT.
 *
 * When enabled, this instance participates as a DHT storage node, storing
 * encrypted message envelopes for other peers.
 *
 * @param enabled true to enable DHT storage, false to disable.
 */
void tox_set_dht_store_enabled(Tox *tox, bool enabled);

#ifdef __cplusplus
}
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_OFFLINE_MSG_H */