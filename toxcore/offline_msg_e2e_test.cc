// clang-format off
#include "../testing/support/public/simulated_environment.hh"
#include "DHT_store.h"
#include "offline_msg.h"
// clang-format on

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "crypto_core.h"
#include "mono_time.h"

namespace {

using tox::test::SimulatedEnvironment;

/**
 * @brief Full end-to-end test: Alice sends an offline message to Bob.
 *
 * Flow:
 * 1. Alice creates an encrypted envelope for Bob
 * 2. Alice's client stores the envelope in the DHT under Bob's key
 * 3. Bob comes online, queries the DHT for his key
 * 4. Bob retrieves the envelope, decrypts it, and reads the message
 */

struct TestKeys {
    std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE> alice_enc_pk;
    std::array<uint8_t, CRYPTO_SECRET_KEY_SIZE> alice_enc_sk;
    std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE> bob_enc_pk;
    std::array<uint8_t, CRYPTO_SECRET_KEY_SIZE> bob_enc_sk;
};

TestKeys make_keys(SimulatedEnvironment &env)
{
    TestKeys keys;
    Extended_Public_Key apub;
    Extended_Secret_Key asec;
    Extended_Public_Key bpub;
    Extended_Secret_Key bsec;

    create_extended_keypair(&apub, &asec, &env.fake_random());
    create_extended_keypair(&bpub, &bsec, &env.fake_random());

    memcpy(keys.alice_enc_pk.data(), get_enc_key(&apub), CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(keys.alice_enc_sk.data(), get_enc_key(&asec), CRYPTO_SECRET_KEY_SIZE);
    memcpy(keys.bob_enc_pk.data(), get_enc_key(&bpub), CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(keys.bob_enc_sk.data(), get_enc_key(&bsec), CRYPTO_SECRET_KEY_SIZE);

    return keys;
}

/**
 * Derive a DHT key for Bob's offline messages.
 * In production, this is: SHA256(bob_enc_pk || "tox-offline-msg-v1" || seq_num)
 */
std::array<uint8_t, DHT_STORE_KEY_SIZE> derive_bob_key(
    const std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE> &bob_pk, uint64_t seq)
{
    std::array<uint8_t, DHT_STORE_KEY_SIZE> key;
    // Simplified: use bob's pubkey as the first 32 bytes
    memcpy(key.data(), bob_pk.data(), CRYPTO_PUBLIC_KEY_SIZE);
    // In production: key = SHA256(bob_pk || domain_sep || seq)
    (void)seq;
    return key;
}

TEST(OfflineMsgE2E, AliceSendsBobOffline)
{
    SimulatedEnvironment env{123};
    auto keys = make_keys(env);

    // Set up DHT store (acts as a DHT node's storage)
    auto store = std::unique_ptr<DHT_Store, void (*)(DHT_Store *)>(
        dht_store_new(env.memory(), env.mono_time()), dht_store_kill);

    // --- Step 1: Alice creates an encrypted envelope ---
    const char *text = "Hey Bob, this is an offline message from Alice!";
    const uint16_t text_len = (uint16_t)strlen(text);
    const uint64_t msg_id = UINT64_C(0xCAFE000000000001);

    uint8_t envelope[OFFLINE_MSG_MAX_ENVELOPE];
    uint16_t envelope_len = 0;

    ASSERT_TRUE(offline_msg_create_envelope(
        env.memory(), &env.fake_random(), env.mono_time(),
        keys.alice_enc_pk.data(), keys.alice_enc_sk.data(),
        keys.bob_enc_pk.data(),
        msg_id, OFFLINE_MSG_TYPE_NORMAL,
        (const uint8_t *)text, text_len,
        envelope, &envelope_len));

    // --- Step 2: Alice stores the envelope in the DHT under Bob's key ---
    const auto bob_dht_key = derive_bob_key(keys.bob_enc_pk, 0);
    ASSERT_TRUE(dht_store_put(store.get(), bob_dht_key.data(),
        envelope, envelope_len, DHT_STORE_DEFAULT_TTL));

    EXPECT_EQ(dht_store_entry_count(store.get()), 1u);

    // --- Step 3: Bob comes online and queries the DHT ---
    const uint8_t *stored = nullptr;
    uint16_t stored_len = 0;
    ASSERT_TRUE(dht_store_get(store.get(), bob_dht_key.data(), &stored, &stored_len));
    EXPECT_EQ(stored_len, envelope_len);

    // --- Step 4: Bob decrypts the envelope ---
    Offline_Msg msg;
    ASSERT_TRUE(offline_msg_open_envelope(
        env.memory(), keys.bob_enc_sk.data(),
        stored, stored_len, &msg));

    EXPECT_EQ(msg.message_id, msg_id);
    EXPECT_EQ(msg.type, OFFLINE_MSG_TYPE_NORMAL);
    EXPECT_EQ(msg.data_length, text_len);
    EXPECT_EQ(memcmp(msg.data, text, text_len), 0);
    EXPECT_EQ(memcmp(msg.sender_pubkey, keys.alice_enc_pk.data(), CRYPTO_PUBLIC_KEY_SIZE), 0);
}

TEST(OfflineMsgE2E, MultipleMessagesSameRecipient)
{
    SimulatedEnvironment env{124};
    auto keys = make_keys(env);

    auto store = std::unique_ptr<DHT_Store, void (*)(DHT_Store *)>(
        dht_store_new(env.memory(), env.mono_time()), dht_store_kill);

    const auto bob_dht_key = derive_bob_key(keys.bob_enc_pk, 0);

    // Alice sends 5 messages
    for (int i = 0; i < 5; ++i) {
        char buf[100];
        snprintf(buf, sizeof(buf), "Message #%d from Alice", i + 1);
        const uint16_t len = (uint16_t)strlen(buf);

        uint8_t envelope[OFFLINE_MSG_MAX_ENVELOPE];
        uint16_t envelope_len = 0;

        ASSERT_TRUE(offline_msg_create_envelope(
            env.memory(), &env.fake_random(), env.mono_time(),
            keys.alice_enc_pk.data(), keys.alice_enc_sk.data(),
            keys.bob_enc_pk.data(),
            (uint64_t)(i + 1), OFFLINE_MSG_TYPE_NORMAL,
            (const uint8_t *)buf, len,
            envelope, &envelope_len));

        ASSERT_TRUE(dht_store_put(store.get(), bob_dht_key.data(),
            envelope, envelope_len, DHT_STORE_DEFAULT_TTL));
    }

    EXPECT_EQ(dht_store_entry_count(store.get()), 5u);

    // Bob retrieves all messages
    uint32_t count = 0;
    const DHT_Store_Entry *entries = dht_store_get_all(
        store.get(), bob_dht_key.data(), &count);
    ASSERT_NE(entries, nullptr);
    EXPECT_EQ(count, 5u);

    // Verify each one can be decrypted
    int verified = 0;
    for (const DHT_Store_Entry *e = entries;
         e != nullptr && verified < 5; e = e->next) {
        if (memcmp(e->key, bob_dht_key.data(), DHT_STORE_KEY_SIZE) != 0) {
            continue;
        }
        Offline_Msg msg;
        ASSERT_TRUE(offline_msg_open_envelope(
            env.memory(), keys.bob_enc_sk.data(),
            e->data, e->data_length, &msg));

        EXPECT_EQ(memcmp(msg.sender_pubkey, keys.alice_enc_pk.data(),
                         CRYPTO_PUBLIC_KEY_SIZE), 0);
        ++verified;
    }
    EXPECT_EQ(verified, 5);
}

TEST(OfflineMsgE2E, ExpiredMessageNotDelivered)
{
    SimulatedEnvironment env{125};
    auto keys = make_keys(env);

    auto store = std::unique_ptr<DHT_Store, void (*)(DHT_Store *)>(
        dht_store_new(env.memory(), env.mono_time()), dht_store_kill);

    const auto bob_dht_key = derive_bob_key(keys.bob_enc_pk, 0);

    // Alice sends a message with 1 second TTL
    const char *text = "This message expires quickly";
    const uint16_t text_len = (uint16_t)strlen(text);

    uint8_t envelope[OFFLINE_MSG_MAX_ENVELOPE];
    uint16_t envelope_len = 0;

    ASSERT_TRUE(offline_msg_create_envelope(
        env.memory(), &env.fake_random(), env.mono_time(),
        keys.alice_enc_pk.data(), keys.alice_enc_sk.data(),
        keys.bob_enc_pk.data(),
        1, OFFLINE_MSG_TYPE_NORMAL,
        (const uint8_t *)text, text_len,
        envelope, &envelope_len));

    ASSERT_TRUE(dht_store_put(store.get(), bob_dht_key.data(),
        envelope, envelope_len, 1));  // 1 second TTL

    // Advance past TTL
    env.advance_time(2000);
    mono_time_update(env.mono_time());

    // Evict expired
    EXPECT_EQ(dht_store_evict_expired(store.get()), 1u);

    // Bob queries — no messages
    const uint8_t *stored = nullptr;
    uint16_t stored_len = 0;
    ASSERT_FALSE(dht_store_get(store.get(), bob_dht_key.data(), &stored, &stored_len));
}

}  // namespace