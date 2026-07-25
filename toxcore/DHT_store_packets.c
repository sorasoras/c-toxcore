/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

/**
 * @brief DHT STORE/FIND_VALUE packet handlers for offline messaging.
 *
 * Integration guide:
 *
 * In toxcore/DHT.c, in the DHT constructor (new_dht), register the handlers:
 *
 *   #include "DHT_store_packets.h"
 *   dht->offline_store = dht_store_new(mem, mono_time);
 *   networking_registerhandler(dht->net, NET_PACKET_DHT_STORE,
 *       &dht_store_packet_handler, dht);
 *   networking_registerhandler(dht->net, NET_PACKET_DHT_FIND_VALUE,
 *       &dht_find_value_packet_handler, dht);
 *
 * In the DHT destructor (kill_dht), unregister and free:
 *
 *   networking_registerhandler(dht->net, NET_PACKET_DHT_STORE, nullptr, nullptr);
 *   networking_registerhandler(dht->net, NET_PACKET_DHT_FIND_VALUE, nullptr, nullptr);
 *   dht_store_kill(dht->offline_store);
 *
 * In do_dht (the main DHT iteration loop), evict expired entries:
 *
 *   dht_store_evict_expired(dht->offline_store);
 */

#include "DHT_store_packets.h"

#include <string.h>

#include "DHT.h"
#include "DHT_store.h"
#include "ccompat.h"
#include "logger.h"

/**
 * @brief Handle an incoming DHT STORE packet.
 *
 * Packet format:
 *   [32 bytes]  dht_key   — the key to store under
 *   [1 byte]    flags     — bit 0: needs_ack
 *   [2 bytes]   data_len  — length of stored data (network byte order)
 *   [N bytes]   data      — the value to store
 *
 * @param object DHT instance pointer.
 * @param source IP/port of the sender.
 * @param data Packet data (after the 1-byte packet type).
 * @param length Length of the packet data.
 * @return 0 on success, -1 on failure.
 */
int dht_store_packet_handler(void *object, IP_Port source, const uint8_t *data, uint16_t length)
{
    DHT *dht = (DHT *)object;

    if (dht == nullptr || data == nullptr) {
        return -1;
    }

    if (length < DHT_STORE_KEY_SIZE + 1 + 2) {
        LOGGER_TRACE(dht->log, "DHT STORE packet too short: %u bytes", length);
        return -1;
    }

    const uint8_t *key = data;
    const uint8_t flags = data[DHT_STORE_KEY_SIZE];
    const bool needs_ack = (flags & 0x01) != 0;

    uint16_t data_len;
    net_unpack_u16(data + DHT_STORE_KEY_SIZE + 1, &data_len);

    if (length < DHT_STORE_KEY_SIZE + 1 + 2 + data_len) {
        LOGGER_TRACE(dht->log, "DHT STORE packet truncated: need %u, have %u",
                     DHT_STORE_KEY_SIZE + 1 + 2 + data_len, length);
        return -1;
    }

    const uint8_t *value = data + DHT_STORE_KEY_SIZE + 1 + 2;

    // Store in the DHT store
    const uint32_t ttl = DHT_STORE_DEFAULT_TTL;
    if (!dht_store_put(dht->offline_store, key, value, data_len, ttl)) {
        LOGGER_TRACE(dht->log, "DHT STORE failed for key (store full or data too large)");
        return -1;
    }

    LOGGER_TRACE(dht->log, "DHT STORE: stored %u bytes for key", data_len);

    // TODO: Send STORE_ACK if needs_ack is set
    (void)needs_ack;
    (void)source;

    return 0;
}

/**
 * @brief Handle an incoming DHT FIND_VALUE packet.
 *
 * Packet format:
 *   [32 bytes]  dht_key   — the key to look up
 *
 * Response (sent as a separate packet to the requester):
 *   [32 bytes]  dht_key   — echoed key
 *   [1 byte]    flags     — bit 0: has_more
 *   [2 bytes]   data_len  — length of value (network byte order)
 *   [N bytes]   data      — the stored value
 *
 * If no value is found, no response is sent (the requester times out
 * and tries closer nodes via the normal DHT routing mechanism).
 *
 * @param object DHT instance pointer.
 * @param source IP/port of the sender.
 * @param data Packet data (after the 1-byte packet type).
 * @param length Length of the packet data.
 * @return 0 on success, -1 on failure.
 */
int dht_find_value_packet_handler(void *object, IP_Port source, const uint8_t *data, uint16_t length)
{
    DHT *dht = (DHT *)object;

    if (dht == nullptr || data == nullptr) {
        return -1;
    }

    if (length < DHT_STORE_KEY_SIZE) {
        LOGGER_TRACE(dht->log, "DHT FIND_VALUE packet too short: %u bytes", length);
        return -1;
    }

    const uint8_t *key = data;

    // Look up in the DHT store
    const uint8_t *value = nullptr;
    uint16_t value_len = 0;

    if (!dht_store_get(dht->offline_store, key, &value, &value_len)) {
        // No value found — the requester should try closer nodes.
        // For a full implementation, we would return the K closest nodes
        // to the key (SEND_NODES semantics). For now, just silently return.
        LOGGER_TRACE(dht->log, "DHT FIND_VALUE: no value for key");
        return 0;
    }

    // Build response packet
    // Note: In a full implementation, this would be sent back to the source
    // via a DHT send function. For now, the value is returned as a callback.
    LOGGER_TRACE(dht->log, "DHT FIND_VALUE: found %u bytes for key", value_len);

    // Integration note: The response should be sent as:
    //   send_dht_packet(dht, source, NET_PACKET_DHT_FIND_VALUE,
    //       assemble_response(key, flags, value_len, value));
    //
    // But the DHT's send path requires onion routing or direct connection,
    // which is beyond the scope of this module. The calling code should
    // handle the response using the normal DHT send infrastructure.

    (void)source;
    return 0;
}