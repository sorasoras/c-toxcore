/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

/**
 * @brief DHT-based key-value storage with TTL for offline messaging.
 *
 * This module provides a bounded, TTL-based key-value store intended for
 * storing encrypted offline message envelopes in the DHT. Each entry is
 * associated with a 32-byte DHT key and automatically evicted when its
 * TTL expires or when storage limits are exceeded.
 *
 * Thread safety: The store uses a pthread rwlock internally. All public
 * functions acquire the appropriate lock.
 */
#ifndef C_TOXCORE_TOXCORE_DHT_STORE_H
#define C_TOXCORE_TOXCORE_DHT_STORE_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"
#include "mem.h"
#include "mono_time.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum number of entries that can be stored per DHT key. */
#define DHT_STORE_MAX_ENTRIES_PER_KEY 100

/** Default maximum total entries across all keys. */
#define DHT_STORE_MAX_TOTAL_ENTRIES 4096

/** Default maximum storage (in bytes) for data across all entries. */
#define DHT_STORE_MAX_TOTAL_SIZE (10u * 1024u * 1024u)

/** Default TTL for stored entries (in seconds). 0 = no automatic eviction. */
#define DHT_STORE_DEFAULT_TTL (7u * 24u * 60u * 60u)

/** Size of a DHT key in bytes (SHA-256 hash). */
#define DHT_STORE_KEY_SIZE 32

/** Maximum size of a single stored data blob. */
#define DHT_STORE_MAX_DATA_SIZE 4096

/**
 * @brief A single stored entry in the DHT store.
 */
typedef struct DHT_Store_Entry {
    uint8_t key[DHT_STORE_KEY_SIZE];     /**< 32-byte DHT key */
    uint8_t *_Nullable data;             /**< Stored data (NULL if deleted) */
    uint16_t data_length;                /**< Length of stored data */
    uint64_t expiration_time;            /**< Monotonic time when this entry expires */
    struct DHT_Store_Entry *_Nullable next; /**< Next entry in the same key bucket */
} DHT_Store_Entry;

/**
 * @brief Configuration for a DHT store instance.
 */
typedef struct DHT_Store_Config {
    uint32_t max_total_entries;          /**< Maximum entries across all keys (default: 4096) */
    uint32_t max_total_size;             /**< Maximum total data bytes (default: 10 MB) */
    uint32_t max_entries_per_key;        /**< Maximum entries per key (default: 100) */
    uint32_t default_ttl_seconds;        /**< Default TTL for new entries (default: 7 days) */
} DHT_Store_Config;

/**
 * @brief A bounded, TTL-based key-value store.
 */
typedef struct DHT_Store {
    const Memory *_Nonnull mem;
    const Mono_Time *_Nonnull mono_time;
    DHT_Store_Config config;

    DHT_Store_Entry *_Nullable *_Nullable buckets; /**< Hash table buckets */
    uint32_t num_buckets;               /**< Number of hash table buckets */
    uint32_t num_entries;               /**< Current number of stored entries */
    uint32_t total_data_size;           /**< Current total size of stored data */
} DHT_Store;

/**
 * @brief Create a new DHT store with the default configuration.
 *
 * @param mem Memory allocator.
 * @param mono_time Monotonic clock for TTL tracking.
 * @return A new DHT_Store, or NULL on allocation failure.
 */
DHT_Store *_Nullable dht_store_new(const Memory *_Nonnull mem, const Mono_Time *_Nonnull mono_time);

/**
 * @brief Create a new DHT store with custom configuration.
 */
DHT_Store *_Nullable dht_store_new_with_config(
    const Memory *_Nonnull mem, const Mono_Time *_Nonnull mono_time,
    const DHT_Store_Config *_Nonnull config);

/**
 * @brief Destroy a DHT store and free all associated memory.
 */
void dht_store_kill(DHT_Store *_Nullable store);

/**
 * @brief Store data under a given DHT key.
 *
 * If the per-key entry limit is reached, the oldest entry for that key
 * is evicted. If the total entry or size limit is reached, the oldest
 * entry globally is evicted.
 *
 * @param store The DHT store.
 * @param key 32-byte DHT key to store under.
 * @param data Data to store (copied internally).
 * @param data_length Length of the data.
 * @param ttl_seconds TTL in seconds (0 = use default).
 * @return true on success, false if allocation fails or data is too large.
 */
bool dht_store_put(DHT_Store *_Nonnull store, const uint8_t key[DHT_STORE_KEY_SIZE],
                   const uint8_t *_Nonnull data, uint16_t data_length,
                   uint32_t ttl_seconds);

/**
 * @brief Retrieve the most recent entry for a given DHT key.
 *
 * @param store The DHT store.
 * @param key 32-byte DHT key to look up.
 * @param data Output pointer set to the stored data (borrowed reference, do not free).
 * @param data_length Output: length of the stored data.
 * @return true if an entry was found and is not expired.
 */
bool dht_store_get(const DHT_Store *_Nonnull store, const uint8_t key[DHT_STORE_KEY_SIZE],
                   const uint8_t **_Nullable data, uint16_t *_Nonnull data_length);

/**
 * @brief Retrieve all entries for a given DHT key.
 *
 * Call @ref dht_store_get_entry_data on each returned entry to access the data.
 *
 * @param store The DHT store.
 * @param key 32-byte DHT key to look up.
 * @param count Output: number of entries returned.
 * @return Linked list of entries (borrowed reference), or NULL if none found.
 *         Entries are returned newest-first.
 */
const DHT_Store_Entry *_Nullable dht_store_get_all(
    const DHT_Store *_Nonnull store, const uint8_t key[DHT_STORE_KEY_SIZE],
    uint32_t *_Nonnull count);

/**
 * @brief Delete a specific entry from the store.
 *
 * @param store The DHT store.
 * @param entry The entry to delete (obtained from @ref dht_store_get_all).
 * @return true if the entry was deleted.
 */
bool dht_store_delete_entry(DHT_Store *_Nonnull store, DHT_Store_Entry *_Nonnull entry);

/**
 * @brief Delete all entries for a given DHT key.
 *
 * @param store The DHT store.
 * @param key 32-byte DHT key.
 * @return Number of entries deleted.
 */
uint32_t dht_store_delete_key(DHT_Store *_Nonnull store, const uint8_t key[DHT_STORE_KEY_SIZE]);

/**
 * @brief Evict all expired entries from the store.
 *
 * Should be called periodically (e.g., once per tox_iterate).
 *
 * @param store The DHT store.
 * @return Number of entries evicted.
 */
uint32_t dht_store_evict_expired(DHT_Store *_Nonnull store);

/**
 * @brief Get the current number of stored entries.
 */
uint32_t dht_store_entry_count(const DHT_Store *_Nonnull store);

/**
 * @brief Get the current total size of stored data in bytes.
 */
uint32_t dht_store_total_size(const DHT_Store *_Nonnull store);

/**
 * @brief Remove all entries from the store.
 */
void dht_store_clear(DHT_Store *_Nonnull store);

#ifdef __cplusplus
}
#endif

#endif /* C_TOXCORE_TOXCORE_DHT_STORE_H */