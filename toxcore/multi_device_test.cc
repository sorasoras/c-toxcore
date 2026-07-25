// clang-format off
#include "../testing/support/public/simulated_environment.hh"
#include "multi_device.h"
// clang-format on

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>

#include "crypto_core.h"
#include "mono_time.h"

namespace {

using tox::test::SimulatedEnvironment;

struct TestKeys {
    std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE> master_pk;
    std::array<uint8_t, CRYPTO_SECRET_KEY_SIZE> master_sk;
    std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE> device_pk;
    std::array<uint8_t, CRYPTO_SECRET_KEY_SIZE> device_sk;
};

TestKeys make_keys(SimulatedEnvironment &env)
{
    TestKeys keys;
    crypto_new_keypair(&env.fake_random(), keys.master_pk.data(), keys.master_sk.data());
    crypto_new_keypair(&env.fake_random(), keys.device_pk.data(), keys.device_sk.data());
    return keys;
}

TEST(MultiDeviceTest, NewListIsEmpty)
{
    SimulatedEnvironment env{1};
    auto keys = make_keys(env);

    auto list = std::unique_ptr<Multi_Device_List, void (*)(Multi_Device_List *)>(
        multi_device_list_new(env.memory(), keys.master_pk.data()),
        multi_device_list_free);

    ASSERT_NE(list, nullptr);
    EXPECT_EQ(list->num_devices, 0);
}

TEST(MultiDeviceTest, AddAndFindDevice)
{
    SimulatedEnvironment env{2};
    auto keys = make_keys(env);

    auto list = std::unique_ptr<Multi_Device_List, void (*)(Multi_Device_List *)>(
        multi_device_list_new(env.memory(), keys.master_pk.data()),
        multi_device_list_free);

    ASSERT_TRUE(multi_device_list_add(
        list.get(), keys.master_sk.data(),
        keys.device_pk.data(), keys.device_sk.data(),
        "TestPhone", 9, env.mono_time(), 3600));

    EXPECT_EQ(list->num_devices, 1);
    EXPECT_GE(multi_device_list_find(list.get(), keys.device_pk.data()), 0);
}

TEST(MultiDeviceTest, AddDuplicateFails)
{
    SimulatedEnvironment env{3};
    auto keys = make_keys(env);

    auto list = std::unique_ptr<Multi_Device_List, void (*)(Multi_Device_List *)>(
        multi_device_list_new(env.memory(), keys.master_pk.data()),
        multi_device_list_free);

    ASSERT_TRUE(multi_device_list_add(
        list.get(), keys.master_sk.data(),
        keys.device_pk.data(), keys.device_sk.data(),
        "Phone", 5, env.mono_time(), 3600));

    EXPECT_FALSE(multi_device_list_add(
        list.get(), keys.master_sk.data(),
        keys.device_pk.data(), keys.device_sk.data(),
        "Phone2", 6, env.mono_time(), 3600));

    EXPECT_EQ(list->num_devices, 1);
}

TEST(MultiDeviceTest, RemoveDevice)
{
    SimulatedEnvironment env{4};
    auto keys = make_keys(env);

    auto list = std::unique_ptr<Multi_Device_List, void (*)(Multi_Device_List *)>(
        multi_device_list_new(env.memory(), keys.master_pk.data()),
        multi_device_list_free);

    ASSERT_TRUE(multi_device_list_add(
        list.get(), keys.master_sk.data(),
        keys.device_pk.data(), keys.device_sk.data(),
        "Phone", 5, env.mono_time(), 3600));

    EXPECT_EQ(list->num_devices, 1);

    ASSERT_TRUE(multi_device_list_remove(list.get(), keys.device_pk.data()));
    EXPECT_EQ(list->num_devices, 0);
}

TEST(MultiDeviceTest, RemoveNonexistent)
{
    SimulatedEnvironment env{5};
    auto keys = make_keys(env);

    auto list = std::unique_ptr<Multi_Device_List, void (*)(Multi_Device_List *)>(
        multi_device_list_new(env.memory(), keys.master_pk.data()),
        multi_device_list_free);

    EXPECT_FALSE(multi_device_list_remove(list.get(), keys.device_pk.data()));
}

TEST(MultiDeviceTest, VerifyValidCert)
{
    SimulatedEnvironment env{6};
    auto keys = make_keys(env);

    auto list = std::unique_ptr<Multi_Device_List, void (*)(Multi_Device_List *)>(
        multi_device_list_new(env.memory(), keys.master_pk.data()),
        multi_device_list_free);

    ASSERT_TRUE(multi_device_list_add(
        list.get(), keys.master_sk.data(),
        keys.device_pk.data(), keys.device_sk.data(),
        "Phone", 5, env.mono_time(), 3600));

    EXPECT_EQ(multi_device_list_verify(list.get()), 1);
}

TEST(MultiDeviceTest, RejectWrongMaster)
{
    SimulatedEnvironment env{7};
    auto keys = make_keys(env);

    // Create list with master_pk but sign with different master_sk
    std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE> fake_master_pk;
    std::array<uint8_t, CRYPTO_SECRET_KEY_SIZE> fake_master_sk;
    crypto_new_keypair(&env.fake_random(), fake_master_pk.data(), fake_master_sk.data());

    auto list = std::unique_ptr<Multi_Device_List, void (*)(Multi_Device_List *)>(
        multi_device_list_new(env.memory(), keys.master_pk.data()),
        multi_device_list_free);

    // Sign with wrong master key
    ASSERT_TRUE(multi_device_list_add(
        list.get(), fake_master_sk.data(),
        keys.device_pk.data(), keys.device_sk.data(),
        "Fake", 4, env.mono_time(), 3600));

    // Signature won't verify against the stored master_pubkey
    EXPECT_EQ(multi_device_list_verify(list.get()), 0);
}

TEST(MultiDeviceTest, MaxDevices)
{
    SimulatedEnvironment env{8};
    auto keys = make_keys(env);

    auto list = std::unique_ptr<Multi_Device_List, void (*)(Multi_Device_List *)>(
        multi_device_list_new(env.memory(), keys.master_pk.data()),
        multi_device_list_free);

    for (int i = 0; i < MULTI_DEVICE_MAX_DEVICES; ++i) {
        std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE> dpk;
        std::array<uint8_t, CRYPTO_SECRET_KEY_SIZE> dsk;
        crypto_new_keypair(&env.fake_random(), dpk.data(), dsk.data());

        char name[20];
        snprintf(name, sizeof(name), "Device%d", i);
        ASSERT_TRUE(multi_device_list_add(
            list.get(), keys.master_sk.data(),
            dpk.data(), dsk.data(),
            name, (uint16_t)strlen(name), env.mono_time(), 3600));
    }

    EXPECT_EQ(list->num_devices, MULTI_DEVICE_MAX_DEVICES);

    // Adding one more should fail
    std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE> extra_pk;
    std::array<uint8_t, CRYPTO_SECRET_KEY_SIZE> extra_sk;
    crypto_new_keypair(&env.fake_random(), extra_pk.data(), extra_sk.data());

    EXPECT_FALSE(multi_device_list_add(
        list.get(), keys.master_sk.data(),
        extra_pk.data(), extra_sk.data(),
        "Extra", 5, env.mono_time(), 3600));
}

TEST(MultiDeviceTest, PackUnpackRoundTrip)
{
    SimulatedEnvironment env{9};
    auto keys = make_keys(env);

    auto list = std::unique_ptr<Multi_Device_List, void (*)(Multi_Device_List *)>(
        multi_device_list_new(env.memory(), keys.master_pk.data()),
        multi_device_list_free);

    ASSERT_TRUE(multi_device_list_add(
        list.get(), keys.master_sk.data(),
        keys.device_pk.data(), keys.device_sk.data(),
        "Phone", 5, env.mono_time(), 3600));

    // Pack
    Bin_Pack *bp = bin_pack_new(env.memory());
    ASSERT_NE(bp, nullptr);
    ASSERT_TRUE(multi_device_list_pack(list.get(), bp));
    uint32_t packed_size;
    uint8_t *packed_data = bin_pack_data(bp, &packed_size);
    ASSERT_NE(packed_data, nullptr);

    // Unpack into a new list
    auto list2 = std::unique_ptr<Multi_Device_List, void (*)(Multi_Device_List *)>(
        multi_device_list_new(env.memory(), keys.master_pk.data()),
        multi_device_list_free);

    Bin_Unpack *bu = bin_unpack_new(env.memory(), packed_data, packed_size, nullptr);
    ASSERT_NE(bu, nullptr);
    ASSERT_TRUE(multi_device_list_unpack(list2.get(), bu));

    EXPECT_EQ(list2->num_devices, 1);
    EXPECT_EQ(memcmp(list2->master_pubkey, keys.master_pk.data(), CRYPTO_PUBLIC_KEY_SIZE), 0);
    EXPECT_EQ(memcmp(list2->devices[0].device_pubkey, keys.device_pk.data(), CRYPTO_PUBLIC_KEY_SIZE), 0);
    EXPECT_EQ(list2->devices[0].name_length, 5);
    EXPECT_EQ(memcmp(list2->devices[0].device_name, "Phone", 5), 0);
    EXPECT_EQ(multi_device_list_verify(list2.get()), 1);

    bin_pack_free(bp);
    bin_unpack_free(bu);
}

}  // namespace