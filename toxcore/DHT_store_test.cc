// clang-format off
#include "../testing/support/public/simulated_environment.hh"
#include "DHT_store.h"
// clang-format on

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>

#include "mono_time.h"

namespace {

using tox::test::SimulatedEnvironment;
using DhtKey = std::array<uint8_t, DHT_STORE_KEY_SIZE>;

/**
 * Helper: create a DHT store backed by the simulated environment.
 */
std::unique_ptr<DHT_Store, void (*)(DHT_Store *)> make_store(SimulatedEnvironment &env)
{
    DHT_Store *store = dht_store_new(env.memory(), env.mono_time());
    return {store, dht_store_kill};
}

/**
 * Helper: fill a DHT key with a test pattern.
 */
DhtKey make_key(uint8_t seed)
{
    DhtKey key;
    for (size_t i = 0; i < DHT_STORE_KEY_SIZE; ++i) {
        key[i] = static_cast<uint8_t>(seed + i);
    }
    return key;
}

/**
 * Helper: fill test data with a pattern.
 */
std::vector<uint8_t> make_data(uint16_t length, uint8_t seed)
{
    std::vector<uint8_t> data(length);
    for (uint16_t i = 0; i < length; ++i) {
        data[i] = static_cast<uint8_t>(seed + i);
    }
    return data;
}

// --- Basic put/get ---

TEST(DhtStoreTest, PutAndGetSingleEntry)
{
    SimulatedEnvironment env{42};
    auto store = make_store(env);

    const auto key = make_key(1);
    const auto data = make_data(100, 42);

    ASSERT_TRUE(dht_store_put(store.get(), key.data(), data.data(), data.size(), 3600));

    const uint8_t *retrieved = nullptr;
    uint16_t retrieved_len = 0;
    ASSERT_TRUE(dht_store_get(store.get(), key.data(), &retrieved, &retrieved_len));
    ASSERT_EQ(retrieved_len, data.size());
    EXPECT_EQ(memcmp(retrieved, data.data(), data.size()), 0);
}

TEST(DhtStoreTest, GetNonExistentKeyReturnsFalse)
{
    SimulatedEnvironment env{42};
    auto store = make_store(env);

    const auto key = make_key(1);
    const uint8_t *data = nullptr;
    uint16_t len = 0;

    ASSERT_FALSE(dht_store_get(store.get(), key.data(), &data, &len));
}

// --- Multiple entries per key ---

TEST(DhtStoreTest, MultipleEntriesSameKey)
{
    SimulatedEnvironment env{42};
    auto store = make_store(env);

    const auto key = make_key(1);

    // Store 3 entries
    for (uint8_t i = 0; i < 3; ++i) {
        const auto data = make_data(50, i);
        ASSERT_TRUE(dht_store_put(store.get(), key.data(), data.data(), data.size(), 3600));
    }

    // get() returns the NEWEST (most recently put)
    const uint8_t *retrieved = nullptr;
    uint16_t retrieved_len = 0;
    ASSERT_TRUE(dht_store_get(store.get(), key.data(), &retrieved, &retrieved_len));
    EXPECT_EQ(retrieved_len, 50u);
    // The most recent was seed=2
    const auto expected = make_data(50, 2);
    EXPECT_EQ(memcmp(retrieved, expected.data(), expected.size()), 0);

    // get_all() returns all entries
    uint32_t count = 0;
    const DHT_Store_Entry *entries = dht_store_get_all(store.get(), key.data(), &count);
    ASSERT_NE(entries, nullptr);
    EXPECT_EQ(count, 3u);
}

// --- Per-key entry limit ---

TEST(DhtStoreTest, PerKeyLimitEvictsOldest)
{
    SimulatedEnvironment env{42};
    auto store = make_store(env);

    const auto key = make_key(1);
    const uint32_t max_per_key = store->config.max_entries_per_key;

    // Fill up to limit
    for (uint32_t i = 0; i < max_per_key; ++i) {
        const auto data = make_data(10, static_cast<uint8_t>(i));
        ASSERT_TRUE(dht_store_put(store.get(), key.data(), data.data(), data.size(), 3600));
    }
    EXPECT_EQ(dht_store_entry_count(store.get()), max_per_key);

    // One more should evict the oldest
    const auto extra_data = make_data(10, 99);
    ASSERT_TRUE(dht_store_put(store.get(), key.data(), extra_data.data(), extra_data.size(), 3600));
    EXPECT_EQ(dht_store_entry_count(store.get()), max_per_key);
}

// --- TTL expiration ---

TEST(DhtStoreTest, ExpiredEntryNotReturned)
{
    SimulatedEnvironment env{42};
    auto store = make_store(env);

    const auto key = make_key(1);
    const auto data = make_data(100, 42);

    // Store with 1 second TTL
    ASSERT_TRUE(dht_store_put(store.get(), key.data(), data.data(), data.size(), 1));

    // Immediately accessible
    const uint8_t *retrieved = nullptr;
    uint16_t retrieved_len = 0;
    ASSERT_TRUE(dht_store_get(store.get(), key.data(), &retrieved, &retrieved_len));

    // Advance time past TTL (1 second = 1000 ms)
    env.advance_time(2000);
    mono_time_update(env.mono_time());

    // Now expired
    ASSERT_FALSE(dht_store_get(store.get(), key.data(), &retrieved, &retrieved_len));
}

TEST(DhtStoreTest, EvictExpiredRemovesEntries)
{
    SimulatedEnvironment env{42};
    auto store = make_store(env);

    const auto key1 = make_key(1);
    const auto key2 = make_key(2);
    const auto data = make_data(50, 42);

    ASSERT_TRUE(dht_store_put(store.get(), key1.data(), data.data(), data.size(), 1));
    ASSERT_TRUE(dht_store_put(store.get(), key2.data(), data.data(), data.size(), 3600));

    EXPECT_EQ(dht_store_entry_count(store.get()), 2u);

    // Advance past the 1s TTL of key1
    env.advance_time(2000);
    mono_time_update(env.mono_time());

    const uint32_t evicted = dht_store_evict_expired(store.get());
    EXPECT_EQ(evicted, 1u);
    EXPECT_EQ(dht_store_entry_count(store.get()), 1u);

    // key1 should be gone, key2 should remain
    const uint8_t *retrieved = nullptr;
    uint16_t retrieved_len = 0;
    ASSERT_FALSE(dht_store_get(store.get(), key1.data(), &retrieved, &retrieved_len));
    ASSERT_TRUE(dht_store_get(store.get(), key2.data(), &retrieved, &retrieved_len));
}

// --- Delete ---

TEST(DhtStoreTest, DeleteKeyRemovesAllEntries)
{
    SimulatedEnvironment env{42};
    auto store = make_store(env);

    const auto key = make_key(1);
    for (uint8_t i = 0; i < 5; ++i) {
        const auto data = make_data(20, i);
        ASSERT_TRUE(dht_store_put(store.get(), key.data(), data.data(), data.size(), 3600));
    }
    EXPECT_EQ(dht_store_entry_count(store.get()), 5u);

    const uint32_t deleted = dht_store_delete_key(store.get(), key.data());
    EXPECT_EQ(deleted, 5u);
    EXPECT_EQ(dht_store_entry_count(store.get()), 0u);
}

TEST(DhtStoreTest, DeleteSingleEntry)
{
    SimulatedEnvironment env{42};
    auto store = make_store(env);

    const auto key = make_key(1);
    const auto data = make_data(100, 42);
    ASSERT_TRUE(dht_store_put(store.get(), key.data(), data.data(), data.size(), 3600));

    uint32_t count = 0;
    DHT_Store_Entry *entry = const_cast<DHT_Store_Entry *>(
        dht_store_get_all(store.get(), key.data(), &count));
    ASSERT_NE(entry, nullptr);

    ASSERT_TRUE(dht_store_delete_entry(store.get(), entry));
    EXPECT_EQ(dht_store_entry_count(store.get()), 0u);
}

// --- Clear ---

TEST(DhtStoreTest, ClearRemovesEverything)
{
    SimulatedEnvironment env{42};
    auto store = make_store(env);

    for (uint8_t k = 0; k < 10; ++k) {
        const auto key = make_key(k);
        const auto data = make_data(50, k);
        ASSERT_TRUE(dht_store_put(store.get(), key.data(), data.data(), data.size(), 3600));
    }
    EXPECT_EQ(dht_store_entry_count(store.get()), 10u);

    dht_store_clear(store.get());
    EXPECT_EQ(dht_store_entry_count(store.get()), 0u);
    EXPECT_EQ(dht_store_total_size(store.get()), 0u);
}

// --- Multiple distinct keys ---

TEST(DhtStoreTest, DistinctKeysDontConflict)
{
    SimulatedEnvironment env{42};
    auto store = make_store(env);

    const auto key_a = make_key(0xAA);
    const auto key_b = make_key(0xBB);
    const auto data_a = make_data(100, 0xAA);
    const auto data_b = make_data(200, 0xBB);

    ASSERT_TRUE(dht_store_put(store.get(), key_a.data(), data_a.data(), data_a.size(), 3600));
    ASSERT_TRUE(dht_store_put(store.get(), key_b.data(), data_b.data(), data_b.size(), 3600));

    const uint8_t *retrieved = nullptr;
    uint16_t retrieved_len = 0;

    ASSERT_TRUE(dht_store_get(store.get(), key_a.data(), &retrieved, &retrieved_len));
    EXPECT_EQ(retrieved_len, data_a.size());
    EXPECT_EQ(memcmp(retrieved, data_a.data(), data_a.size()), 0);

    ASSERT_TRUE(dht_store_get(store.get(), key_b.data(), &retrieved, &retrieved_len));
    EXPECT_EQ(retrieved_len, data_b.size());
    EXPECT_EQ(memcmp(retrieved, data_b.data(), data_b.size()), 0);
}

// --- Null safety ---

TEST(DhtStoreTest, NullStoreSafe)
{
    EXPECT_EQ(dht_store_entry_count(nullptr), 0u);
    EXPECT_EQ(dht_store_total_size(nullptr), 0u);
    EXPECT_EQ(dht_store_evict_expired(nullptr), 0u);
    dht_store_kill(nullptr);
    dht_store_clear(nullptr);

    const uint8_t key[DHT_STORE_KEY_SIZE] = {0};
    const uint8_t *data = nullptr;
    uint16_t len = 0;
    EXPECT_FALSE(dht_store_get(nullptr, key, &data, &len));
    EXPECT_FALSE(dht_store_put(nullptr, key, (const uint8_t *)"x", 1, 0));
    EXPECT_EQ(dht_store_delete_key(nullptr, key), 0u);
    EXPECT_FALSE(dht_store_delete_entry(nullptr, nullptr));

    uint32_t count = 0;
    EXPECT_EQ(dht_store_get_all(nullptr, key, &count), nullptr);
}

// --- Default TTL when 0 passed ---

TEST(DhtStoreTest, ZeroTtlUsesDefault)
{
    SimulatedEnvironment env{42};
    auto store = make_store(env);

    // Override default TTL to 2 seconds for this test
    DHT_Store_Config config = store->config;
    config.default_ttl_seconds = 2;
    auto store2 = std::unique_ptr<DHT_Store, void (*)(DHT_Store *)>(
        dht_store_new_with_config(env.memory(), env.mono_time(), &config),
        dht_store_kill);

    const auto key = make_key(1);
    const auto data = make_data(50, 42);

    ASSERT_TRUE(dht_store_put(store2.get(), key.data(), data.data(), data.size(), 0));

    // Immediately accessible
    const uint8_t *retrieved = nullptr;
    uint16_t retrieved_len = 0;
    ASSERT_TRUE(dht_store_get(store2.get(), key.data(), &retrieved, &retrieved_len));

    // Advance past default 2-second TTL
    env.advance_time(3000);
    mono_time_update(env.mono_time());

    ASSERT_FALSE(dht_store_get(store2.get(), key.data(), &retrieved, &retrieved_len));
}

// --- Data size limit ---

TEST(DhtStoreTest, RejectOversizedData)
{
    SimulatedEnvironment env{42};
    auto store = make_store(env);

    const auto key = make_key(1);
    const auto data = make_data(DHT_STORE_MAX_DATA_SIZE + 1, 42);

    ASSERT_FALSE(dht_store_put(store.get(), key.data(), data.data(), data.size(), 3600));
}

// --- Hash distribution (keys hash to different buckets) ---

TEST(DhtStoreTest, ManyRandomKeys)
{
    SimulatedEnvironment env{42};
    auto store = make_store(env);

    const auto data = make_data(50, 42);
    constexpr int num_keys = 100;

    for (int i = 0; i < num_keys; ++i) {
        const auto key = make_key(static_cast<uint8_t>(i * 7 + 13));
        ASSERT_TRUE(dht_store_put(store.get(), key.data(), data.data(), data.size(), 3600));
    }

    EXPECT_EQ(dht_store_entry_count(store.get()), num_keys);

    // Retrieve each one
    for (int i = 0; i < num_keys; ++i) {
        const auto key = make_key(static_cast<uint8_t>(i * 7 + 13));
        const uint8_t *retrieved = nullptr;
        uint16_t retrieved_len = 0;
        ASSERT_TRUE(dht_store_get(store.get(), key.data(), &retrieved, &retrieved_len));
        EXPECT_EQ(retrieved_len, data.size());
    }
}

}  // namespace