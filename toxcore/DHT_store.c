/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */
#include "DHT_store.h"

#include <string.h>

#include "ccompat.h"

/** Number of hash table buckets. Must be a power of 2. */
#define DHT_STORE_NUM_BUCKETS 256

/** Hash a DHT key to a bucket index. Uses FNV-1a on the first 4 bytes for speed. */
static uint32_t dht_store_hash_key(const uint8_t key[DHT_STORE_KEY_SIZE])
{
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < DHT_STORE_KEY_SIZE; ++i) {
        hash ^= key[i];
        hash *= 16777619u;
    }
    return hash & (DHT_STORE_NUM_BUCKETS - 1);
}

/** Default configuration. */
static const DHT_Store_Config default_config = {
    DHT_STORE_MAX_TOTAL_ENTRIES,
    DHT_STORE_MAX_TOTAL_SIZE,
    DHT_STORE_MAX_ENTRIES_PER_KEY,
    DHT_STORE_DEFAULT_TTL,
};

DHT_Store *dht_store_new(const Memory *mem, const Mono_Time *mono_time)
{
    return dht_store_new_with_config(mem, mono_time, &default_config);
}

DHT_Store *dht_store_new_with_config(
    const Memory *mem, const Mono_Time *mono_time,
    const DHT_Store_Config *config)
{
    if (mem == nullptr || mono_time == nullptr || config == nullptr) {
        return nullptr;
    }

    DHT_Store *store = (DHT_Store *)mem_alloc(mem, sizeof(DHT_Store));
    if (store == nullptr) {
        return nullptr;
    }

    store->mem = mem;
    store->mono_time = mono_time;
    store->config = *config;
    store->num_buckets = DHT_STORE_NUM_BUCKETS;
    store->num_entries = 0;
    store->total_data_size = 0;

    store->buckets = (DHT_Store_Entry **)mem_alloc(mem, sizeof(DHT_Store_Entry *) * DHT_STORE_NUM_BUCKETS);
    if (store->buckets == nullptr) {
        mem_delete(mem, store);
        return nullptr;
    }

    for (uint32_t i = 0; i < DHT_STORE_NUM_BUCKETS; ++i) {
        store->buckets[i] = nullptr;
    }

    return store;
}

void dht_store_kill(DHT_Store *store)
{
    if (store == nullptr) {
        return;
    }

    dht_store_clear(store);
    mem_delete(store->mem, store->buckets);
    mem_delete(store->mem, store);
}

/** Create a new entry (does NOT insert into the store). */
static DHT_Store_Entry *entry_new(const Memory *mem, const uint8_t key[DHT_STORE_KEY_SIZE],
                                  const uint8_t *data, uint16_t data_length,
                                  uint64_t expiration_time)
{
    DHT_Store_Entry *entry = (DHT_Store_Entry *)mem_alloc(mem, sizeof(DHT_Store_Entry));
    if (entry == nullptr) {
        return nullptr;
    }

    memcpy(entry->key, key, DHT_STORE_KEY_SIZE);
    entry->data_length = data_length;
    entry->expiration_time = expiration_time;
    entry->next = nullptr;

    if (data_length > 0 && data != nullptr) {
        entry->data = (uint8_t *)mem_alloc(mem, data_length);
        if (entry->data == nullptr) {
            mem_delete(mem, entry);
            return nullptr;
        }
        memcpy(entry->data, data, data_length);
    } else {
        entry->data = nullptr;
    }

    return entry;
}

/** Free an entry and its data. */
static void entry_free(const Memory *mem, DHT_Store_Entry *entry)
{
    if (entry == nullptr) {
        return;
    }
    mem_delete(mem, entry->data);
    mem_delete(mem, entry);
}

/** Evict the oldest entry globally. Returns true if an entry was evicted. */
static bool evict_oldest_global(DHT_Store *store)
{
    DHT_Store_Entry *oldest = nullptr;
    uint32_t oldest_bucket = 0;

    for (uint32_t i = 0; i < store->num_buckets; ++i) {
        for (DHT_Store_Entry *e = store->buckets[i]; e != nullptr; e = e->next) {
            if (oldest == nullptr || e->expiration_time < oldest->expiration_time) {
                oldest = e;
                oldest_bucket = i;
            }
        }
    }

    if (oldest == nullptr) {
        return false;
    }

    return dht_store_delete_entry(store, oldest);
}

/** Evict the oldest entry for a given key. Returns true if an entry was evicted. */
static bool evict_oldest_for_key(DHT_Store *store, const uint8_t key[DHT_STORE_KEY_SIZE])
{
    const uint32_t bucket = dht_store_hash_key(key);
    DHT_Store_Entry *oldest = nullptr;

    for (DHT_Store_Entry *e = store->buckets[bucket]; e != nullptr; e = e->next) {
        if (memcmp(e->key, key, DHT_STORE_KEY_SIZE) != 0) {
            continue;
        }
        if (oldest == nullptr || e->expiration_time < oldest->expiration_time) {
            oldest = e;
        }
    }

    if (oldest == nullptr) {
        return false;
    }

    return dht_store_delete_entry(store, oldest);
}

/** Count entries for a given key. */
static uint32_t count_entries_for_key(const DHT_Store *store, const uint8_t key[DHT_STORE_KEY_SIZE])
{
    const uint32_t bucket = dht_store_hash_key(key);
    uint32_t count = 0;

    for (const DHT_Store_Entry *e = store->buckets[bucket]; e != nullptr; e = e->next) {
        if (memcmp(e->key, key, DHT_STORE_KEY_SIZE) == 0) {
            ++count;
        }
    }

    return count;
}

bool dht_store_put(DHT_Store *store, const uint8_t key[DHT_STORE_KEY_SIZE],
                   const uint8_t *data, uint16_t data_length,
                   uint32_t ttl_seconds)
{
    if (store == nullptr || key == nullptr || data == nullptr || data_length == 0) {
        return false;
    }

    if (data_length > DHT_STORE_MAX_DATA_SIZE) {
        return false;
    }

    // Evict expired entries first to free up space
    dht_store_evict_expired(store);

    // Enforce per-key entry limit
    while (count_entries_for_key(store, key) >= store->config.max_entries_per_key) {
        if (!evict_oldest_for_key(store, key)) {
            break;  // Should not happen, but avoid infinite loop
        }
    }

    // Enforce total entry limit
    while (store->num_entries >= store->config.max_total_entries) {
        if (!evict_oldest_global(store)) {
            break;
        }
    }

    // Enforce total size limit
    while (store->total_data_size + data_length > store->config.max_total_size) {
        if (!evict_oldest_global(store)) {
            break;
        }
    }

    // Calculate expiration time
    const uint32_t effective_ttl = (ttl_seconds == 0) ? store->config.default_ttl_seconds : ttl_seconds;
    const uint64_t expiration = mono_time_get(store->mono_time) + ((uint64_t)effective_ttl * 1000);

    // Create entry
    DHT_Store_Entry *entry = entry_new(store->mem, key, data, data_length, expiration);
    if (entry == nullptr) {
        return false;
    }

    // Insert at the head of the bucket (newest first)
    const uint32_t bucket = dht_store_hash_key(key);
    entry->next = store->buckets[bucket];
    store->buckets[bucket] = entry;

    store->num_entries++;
    store->total_data_size += data_length;

    return true;
}

bool dht_store_get(const DHT_Store *store, const uint8_t key[DHT_STORE_KEY_SIZE],
                   const uint8_t **data, uint16_t *data_length)
{
    if (store == nullptr || key == nullptr || data == nullptr || data_length == nullptr) {
        return false;
    }

    const uint64_t now = mono_time_get(store->mono_time);
    const uint32_t bucket = dht_store_hash_key(key);

    // Return the newest non-expired entry for this key
    for (const DHT_Store_Entry *e = store->buckets[bucket]; e != nullptr; e = e->next) {
        if (memcmp(e->key, key, DHT_STORE_KEY_SIZE) != 0) {
            continue;
        }
        if (e->expiration_time <= now) {
            continue;  // Expired, skip
        }
        *data = e->data;
        *data_length = e->data_length;
        return true;
    }

    return false;
}

const DHT_Store_Entry *dht_store_get_all(
    const DHT_Store *store, const uint8_t key[DHT_STORE_KEY_SIZE],
    uint32_t *count)
{
    if (store == nullptr || key == nullptr || count == nullptr) {
        return nullptr;
    }

    const uint64_t now = mono_time_get(store->mono_time);
    const uint32_t bucket = dht_store_hash_key(key);

    *count = 0;
    const DHT_Store_Entry *result = nullptr;
    const DHT_Store_Entry **tail = &result;

    for (const DHT_Store_Entry *e = store->buckets[bucket]; e != nullptr; e = e->next) {
        if (memcmp(e->key, key, DHT_STORE_KEY_SIZE) != 0) {
            continue;
        }
        if (e->expiration_time <= now) {
            continue;
        }
        // Build a linked list from the entries we found, newest first.
        // Since we iterate bucket order (newest first), we just add to the result.
        const DHT_Store_Entry **entry_ptr = tail;
        // We can't chain them since they're const and already in a linked list.
        // Instead, just return a pointer to the first one and let the caller
        // iterate via ->next, filtering by key.
        if (*count == 0) {
            result = e;
        }
        ++(*count);
    }

    return result;
}

bool dht_store_delete_entry(DHT_Store *store, DHT_Store_Entry *entry)
{
    if (store == nullptr || entry == nullptr) {
        return false;
    }

    const uint32_t bucket = dht_store_hash_key(entry->key);
    DHT_Store_Entry **prev = &store->buckets[bucket];

    for (DHT_Store_Entry *e = store->buckets[bucket]; e != nullptr; e = e->next) {
        if (e == entry) {
            *prev = e->next;
            store->num_entries--;
            store->total_data_size -= e->data_length;
            entry_free(store->mem, e);
            return true;
        }
        prev = &e->next;
    }

    return false;  // Entry not found
}

uint32_t dht_store_delete_key(DHT_Store *store, const uint8_t key[DHT_STORE_KEY_SIZE])
{
    if (store == nullptr || key == nullptr) {
        return 0;
    }

    uint32_t deleted = 0;
    const uint32_t bucket = dht_store_hash_key(key);
    DHT_Store_Entry **prev = &store->buckets[bucket];

    while (*prev != nullptr) {
        DHT_Store_Entry *e = *prev;
        if (memcmp(e->key, key, DHT_STORE_KEY_SIZE) == 0) {
            *prev = e->next;
            store->num_entries--;
            store->total_data_size -= e->data_length;
            entry_free(store->mem, e);
            ++deleted;
        } else {
            prev = &e->next;
        }
    }

    return deleted;
}

uint32_t dht_store_evict_expired(DHT_Store *store)
{
    if (store == nullptr) {
        return 0;
    }

    uint32_t evicted = 0;
    const uint64_t now = mono_time_get(store->mono_time);

    for (uint32_t i = 0; i < store->num_buckets; ++i) {
        DHT_Store_Entry **prev = &store->buckets[i];

        while (*prev != nullptr) {
            DHT_Store_Entry *e = *prev;
            if (e->expiration_time <= now) {
                *prev = e->next;
                store->num_entries--;
                store->total_data_size -= e->data_length;
                entry_free(store->mem, e);
                ++evicted;
            } else {
                prev = &e->next;
            }
        }
    }

    return evicted;
}

uint32_t dht_store_entry_count(const DHT_Store *store)
{
    return store != nullptr ? store->num_entries : 0;
}

uint32_t dht_store_total_size(const DHT_Store *store)
{
    return store != nullptr ? store->total_data_size : 0;
}

void dht_store_clear(DHT_Store *store)
{
    if (store == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < store->num_buckets; ++i) {
        DHT_Store_Entry *e = store->buckets[i];
        while (e != nullptr) {
            DHT_Store_Entry *next = e->next;
            entry_free(store->mem, e);
            e = next;
        }
        store->buckets[i] = nullptr;
    }

    store->num_entries = 0;
    store->total_data_size = 0;
}