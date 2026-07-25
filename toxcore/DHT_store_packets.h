/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

/**
 * @brief DHT packet handlers for offline message storage and retrieval.
 *
 * These handlers implement the STORE and FIND_VALUE DHT operations
 * for offline messaging. See the .c file for integration instructions.
 */
#ifndef C_TOXCORE_TOXCORE_DHT_STORE_PACKETS_H
#define C_TOXCORE_TOXCORE_DHT_STORE_PACKETS_H

#include "DHT.h"
#include "network.h"

/**
 * @brief Handle an incoming DHT STORE packet (NET_PACKET_DHT_STORE = 0x22).
 *
 * Stores the given value under the given DHT key in the DHT's offline store.
 *
 * Register with: networking_registerhandler(dht->net, NET_PACKET_DHT_STORE,
 *     &dht_store_packet_handler, dht);
 */
int dht_store_packet_handler(void *_Nonnull object, IP_Port source,
    const uint8_t *_Nonnull data, uint16_t length);

/**
 * @brief Handle an incoming DHT FIND_VALUE packet (NET_PACKET_DHT_FIND_VALUE = 0x23).
 *
 * Looks up the given DHT key in the DHT's offline store and returns the
 * stored value, if any.
 *
 * Register with: networking_registerhandler(dht->net, NET_PACKET_DHT_FIND_VALUE,
 *     &dht_find_value_packet_handler, dht);
 */
int dht_find_value_packet_handler(void *_Nonnull object, IP_Port source,
    const uint8_t *_Nonnull data, uint16_t length);

#endif /* C_TOXCORE_TOXCORE_DHT_STORE_PACKETS_H */