// clang-format off
#include "../testing/support/public/simulated_environment.hh"
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

struct TestKeys {
    uint8_t alice_enc_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t alice_enc_sk[CRYPTO_SECRET_KEY_SIZE];
    uint8_t bob_enc_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t bob_enc_sk[CRYPTO_SECRET_KEY_SIZE];
};

TestKeys make_keys(SimulatedEnvironment &env)
{
    TestKeys keys;
    Extended_Public_Key alice_pub;
    Extended_Secret_Key alice_sec;
    Extended_Public_Key bob_pub;
    Extended_Secret_Key bob_sec;

    create_extended_keypair(&alice_pub, &alice_sec, &env.fake_random());
    create_extended_keypair(&bob_pub, &bob_sec, &env.fake_random());

    memcpy(keys.alice_enc_pk, get_enc_key(&alice_pub), CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(keys.alice_enc_sk, get_enc_key(&alice_sec), CRYPTO_SECRET_KEY_SIZE);
    memcpy(keys.bob_enc_pk, get_enc_key(&bob_pub), CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(keys.bob_enc_sk, get_enc_key(&bob_sec), CRYPTO_SECRET_KEY_SIZE);

    return keys;
}

// --- Round-trip ---

TEST(OfflineMsgTest, CreateAndOpenRoundTrip)
{
    SimulatedEnvironment env{99};
    auto keys = make_keys(env);

    const char *message = "Hello Bob! This is an offline message.";
    const uint16_t msg_len = (uint16_t)strlen(message);

    uint8_t envelope[OFFLINE_MSG_MAX_ENVELOPE];
    uint16_t envelope_len = 0;

    ASSERT_TRUE(offline_msg_create_envelope(
        env.memory(), &env.fake_random(), env.mono_time(),
        keys.alice_enc_pk, keys.alice_enc_sk, keys.bob_enc_pk,
        42, OFFLINE_MSG_TYPE_NORMAL,
        (const uint8_t *)message, msg_len,
        envelope, &envelope_len));
    EXPECT_GT(envelope_len, OFFLINE_MSG_OUTER_SIZE);
    EXPECT_LE(envelope_len, OFFLINE_MSG_MAX_ENVELOPE);

    // Bob decrypts
    Offline_Msg msg;
    ASSERT_TRUE(offline_msg_open_envelope(
        env.memory(), keys.bob_enc_sk,
        envelope, envelope_len, &msg));

    EXPECT_EQ(msg.message_id, 42u);
    EXPECT_EQ(msg.type, OFFLINE_MSG_TYPE_NORMAL);
    EXPECT_EQ(msg.data_length, msg_len);
    EXPECT_EQ(memcmp(msg.data, message, msg_len), 0);
    EXPECT_EQ(memcmp(msg.sender_pubkey, keys.alice_enc_pk, CRYPTO_PUBLIC_KEY_SIZE), 0);
}

// --- Wrong recipient cannot decrypt ---

TEST(OfflineMsgTest, WrongRecipientCannotDecrypt)
{
    SimulatedEnvironment env{99};
    auto keys = make_keys(env);

    // Also make a third party (Eve)
    Extended_Public_Key eve_pub;
    Extended_Secret_Key eve_sec;
    create_extended_keypair(&eve_pub, &eve_sec, &env.fake_random());
    uint8_t eve_enc_sk[CRYPTO_SECRET_KEY_SIZE];
    memcpy(eve_enc_sk, get_enc_key(&eve_sec), CRYPTO_SECRET_KEY_SIZE);

    const char *message = "Secret message for Bob";
    const uint16_t msg_len = (uint16_t)strlen(message);

    uint8_t envelope[OFFLINE_MSG_MAX_ENVELOPE];
    uint16_t envelope_len = 0;

    ASSERT_TRUE(offline_msg_create_envelope(
        env.memory(), &env.fake_random(), env.mono_time(),
        keys.alice_enc_pk, keys.alice_enc_sk, keys.bob_enc_pk,
        1, OFFLINE_MSG_TYPE_NORMAL,
        (const uint8_t *)message, msg_len,
        envelope, &envelope_len));

    // Eve tries to decrypt — should fail
    Offline_Msg msg;
    ASSERT_FALSE(offline_msg_open_envelope(
        env.memory(), eve_enc_sk,
        envelope, envelope_len, &msg));
}

// --- Tampered envelope rejected ---

TEST(OfflineMsgTest, TamperedEnvelopeRejected)
{
    SimulatedEnvironment env{99};
    auto keys = make_keys(env);

    const char *message = "Tamper test";
    const uint16_t msg_len = (uint16_t)strlen(message);

    uint8_t envelope[OFFLINE_MSG_MAX_ENVELOPE];
    uint16_t envelope_len = 0;

    ASSERT_TRUE(offline_msg_create_envelope(
        env.memory(), &env.fake_random(), env.mono_time(),
        keys.alice_enc_pk, keys.alice_enc_sk, keys.bob_enc_pk,
        99, OFFLINE_MSG_TYPE_ACTION,
        (const uint8_t *)message, msg_len,
        envelope, &envelope_len));

    // Flip a bit in the ciphertext
    envelope[OFFLINE_MSG_OUTER_SIZE + 1] ^= 0x01;

    Offline_Msg msg;
    ASSERT_FALSE(offline_msg_open_envelope(
        env.memory(), keys.bob_enc_sk,
        envelope, envelope_len, &msg));
}

// --- Short/invalid envelope rejected ---

TEST(OfflineMsgTest, RejectShortEnvelope)
{
    SimulatedEnvironment env{99};
    auto keys = make_keys(env);

    uint8_t short_buf[10] = {0};
    Offline_Msg msg;
    ASSERT_FALSE(offline_msg_open_envelope(
        env.memory(), keys.bob_enc_sk,
        short_buf, sizeof(short_buf), &msg));
}

// --- Null safety ---

TEST(OfflineMsgTest, NullArgumentsRejected)
{
    SimulatedEnvironment env{99};
    auto keys = make_keys(env);

    uint8_t envelope[OFFLINE_MSG_MAX_ENVELOPE];
    uint16_t envelope_len = 0;

    EXPECT_FALSE(offline_msg_create_envelope(
        nullptr, &env.fake_random(), env.mono_time(),
        keys.alice_enc_pk, keys.alice_enc_sk, keys.bob_enc_pk,
        0, OFFLINE_MSG_TYPE_NORMAL,
        (const uint8_t *)"x", 1, envelope, &envelope_len));

    Offline_Msg msg;
    EXPECT_FALSE(offline_msg_open_envelope(nullptr, keys.bob_enc_sk,
        (const uint8_t *)"x", 1, &msg));
    EXPECT_FALSE(offline_msg_open_envelope(env.memory(), keys.bob_enc_sk,
        nullptr, 0, &msg));
}

// --- Oversized message rejected ---

TEST(OfflineMsgTest, RejectOversizedMessage)
{
    SimulatedEnvironment env{99};
    auto keys = make_keys(env);

    std::vector<uint8_t> big_msg(OFFLINE_MSG_MAX_DATA_SIZE + 1, 'x');
    uint8_t envelope[OFFLINE_MSG_MAX_ENVELOPE];
    uint16_t envelope_len = 0;

    ASSERT_FALSE(offline_msg_create_envelope(
        env.memory(), &env.fake_random(), env.mono_time(),
        keys.alice_enc_pk, keys.alice_enc_sk, keys.bob_enc_pk,
        0, OFFLINE_MSG_TYPE_NORMAL,
        big_msg.data(), (uint16_t)big_msg.size(),
        envelope, &envelope_len));
}

// --- Different message_ids produce different envelopes ---

TEST(OfflineMsgTest, DifferentIdsDifferentEnvelopes)
{
    SimulatedEnvironment env{99};
    auto keys = make_keys(env);

    const char *message = "test";
    const uint16_t msg_len = (uint16_t)strlen(message);

    uint8_t env1[OFFLINE_MSG_MAX_ENVELOPE], env2[OFFLINE_MSG_MAX_ENVELOPE];
    uint16_t len1 = 0, len2 = 0;

    ASSERT_TRUE(offline_msg_create_envelope(
        env.memory(), &env.fake_random(), env.mono_time(),
        keys.alice_enc_pk, keys.alice_enc_sk, keys.bob_enc_pk,
        1, OFFLINE_MSG_TYPE_NORMAL,
        (const uint8_t *)message, msg_len,
        env1, &len1));

    ASSERT_TRUE(offline_msg_create_envelope(
        env.memory(), &env.fake_random(), env.mono_time(),
        keys.alice_enc_pk, keys.alice_enc_sk, keys.bob_enc_pk,
        2, OFFLINE_MSG_TYPE_NORMAL,
        (const uint8_t *)message, msg_len,
        env2, &len2));

    EXPECT_EQ(len1, len2);  // same lengths
    // Ciphertexts should differ (different message_ids)
    EXPECT_NE(memcmp(env1 + OFFLINE_MSG_OUTER_SIZE,
                     env2 + OFFLINE_MSG_OUTER_SIZE, len1 - OFFLINE_MSG_OUTER_SIZE), 0);
}

// --- Message type round-trip (action) ---

TEST(OfflineMsgTest, ActionMessageRoundTrip)
{
    SimulatedEnvironment env{99};
    auto keys = make_keys(env);

    const char *message = "/me waves hello";
    const uint16_t msg_len = (uint16_t)strlen(message);

    uint8_t envelope[OFFLINE_MSG_MAX_ENVELOPE];
    uint16_t envelope_len = 0;

    ASSERT_TRUE(offline_msg_create_envelope(
        env.memory(), &env.fake_random(), env.mono_time(),
        keys.alice_enc_pk, keys.alice_enc_sk, keys.bob_enc_pk,
        7, OFFLINE_MSG_TYPE_ACTION,
        (const uint8_t *)message, msg_len,
        envelope, &envelope_len));

    Offline_Msg msg;
    ASSERT_TRUE(offline_msg_open_envelope(
        env.memory(), keys.bob_enc_sk,
        envelope, envelope_len, &msg));

    EXPECT_EQ(msg.type, OFFLINE_MSG_TYPE_ACTION);
    EXPECT_EQ(msg.data_length, msg_len);
}

// --- pack/unpack message_id helpers ---

TEST(OfflineMsgTest, PackUnpackMessageId)
{
    uint8_t buf[8];
    offline_msg_pack_message_id(buf, UINT64_C(0xDEADBEEFCAFE1234));
    const uint64_t id = offline_msg_unpack_message_id(buf);
    EXPECT_EQ(id, UINT64_C(0xDEADBEEFCAFE1234));
}

}  // namespace