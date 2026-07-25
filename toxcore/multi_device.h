/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

/**
 * @brief Multi-device identity management.
 *
 * Allows multiple Tox instances (devices) to share a single Tox ID.
 * A master keypair identifies the user. Each device generates its own
 * subkey, which is signed by the master key to create a device certificate.
 * Friends can discover all of a user's devices and send messages to
 * any or all of them.
 *
 * ## Architecture
 *
 *   Master Key (Tox ID)
 *     │
 *     ├── Device "Phone"  (subkey, signed cert)
 *     ├── Device "Laptop" (subkey, signed cert)
 *     └── Device "Desktop"(subkey, signed cert)
 *
 * ## Device Certificate Format
 *
 *   [1 byte]   version (0x01)
 *   [32 bytes] device_public_key
 *   [2 bytes]  name_length
 *   [N bytes]  device_name (UTF-8)
 *   [8 bytes]  created_timestamp (ms)
 *   [8 bytes]  expires_timestamp (ms, 0 = never)
 *   [64 bytes] ed25519_signature over all above
 *
 * Total: 1 + 32 + 2 + N + 8 + 8 + 64 = 115 + N bytes
 */
#ifndef C_TOXCORE_TOXCORE_MULTI_DEVICE_H
#define C_TOXCORE_TOXCORE_MULTI_DEVICE_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"
#include "bin_pack.h"
#include "bin_unpack.h"
#include "crypto_core.h"
#include "mem.h"
#include "mono_time.h"
#include "rng.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MULTI_DEVICE_MAX_DEVICES       8
#define MULTI_DEVICE_MAX_NAME_LENGTH    64
#define MULTI_DEVICE_CERT_VERSION       1
#define MULTI_DEVICE_CERT_MAX_SIZE      (1 + CRYPTO_PUBLIC_KEY_SIZE + 2 + MULTI_DEVICE_MAX_NAME_LENGTH + 8 + 8 + CRYPTO_SIGNATURE_SIZE)
#define MULTI_DEVICE_DEFAULT_TTL_SECONDS (90u * 24u * 60u * 60u)  // 90 days

/**
 * @brief A signed certificate binding a device subkey to a master key.
 */
typedef struct Multi_Device_Cert {
    uint8_t device_pubkey[CRYPTO_PUBLIC_KEY_SIZE];
    char device_name[MULTI_DEVICE_MAX_NAME_LENGTH];
    uint16_t name_length;
    uint64_t created_timestamp;
    uint64_t expires_timestamp;
    uint8_t signature[CRYPTO_SIGNATURE_SIZE];
} Multi_Device_Cert;

/**
 * @brief A list of device certificates for one user.
 */
typedef struct Multi_Device_List {
    const Memory *_Nonnull mem;
    Multi_Device_Cert devices[MULTI_DEVICE_MAX_DEVICES];
    uint8_t master_pubkey[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t num_devices;
} Multi_Device_List;

/**
 * @brief Create an empty device list.
 */
Multi_Device_List *_Nullable multi_device_list_new(
    const Memory *_Nonnull mem,
    const uint8_t master_pubkey[CRYPTO_PUBLIC_KEY_SIZE]);

/**
 * @brief Free a device list.
 */
void multi_device_list_free(Multi_Device_List *_Nullable list);

/**
 * @brief Add a device to the list.
 *
 * The device certificate is signed by the master secret key and verified
 * before being added.
 *
 * @param master_seckey The master secret key (must match the stored master pubkey).
 * @param device_pubkey The device's public key.
 * @param device_seckey The device's secret key (used only for signing the cert —
 *        the cert is signed by the MASTER key, not the device key).
 * @param device_name Human-readable name for the device.
 * @param name_length Length of device_name.
 * @param ttl_seconds Time-to-live in seconds (0 = default 90 days).
 * @return true on success.
 */
bool multi_device_list_add(
    Multi_Device_List *_Nonnull list,
    const uint8_t master_seckey[CRYPTO_SECRET_KEY_SIZE],
    const uint8_t device_pubkey[CRYPTO_PUBLIC_KEY_SIZE],
    const uint8_t device_seckey[CRYPTO_SECRET_KEY_SIZE],
    const char *_Nonnull device_name, uint16_t name_length,
    const Mono_Time *_Nonnull mono_time,
    uint32_t ttl_seconds);

/**
 * @brief Remove a device from the list by public key.
 */
bool multi_device_list_remove(
    Multi_Device_List *_Nonnull list,
    const uint8_t device_pubkey[CRYPTO_PUBLIC_KEY_SIZE]);

/**
 * @brief Find a device in the list by public key.
 * @return Index of the device, or -1 if not found.
 */
int multi_device_list_find(
    const Multi_Device_List *_Nonnull list,
    const uint8_t device_pubkey[CRYPTO_PUBLIC_KEY_SIZE]);

/**
 * @brief Verify all certificates in the list are validly signed by the master key.
 * @return Number of valid certificates.
 */
uint8_t multi_device_list_verify(const Multi_Device_List *_Nonnull list);

/**
 * @brief Remove expired certificates from the list.
 * @return Number of certificates removed.
 */
uint8_t multi_device_list_prune_expired(
    Multi_Device_List *_Nonnull list,
    const Mono_Time *_Nonnull mono_time);

/**
 * @brief Serialize a device certificate to bin_pack.
 */
bool multi_device_cert_pack(const Multi_Device_Cert *_Nonnull cert, Bin_Pack *_Nonnull bp);

/**
 * @brief Deserialize a device certificate from bin_unpack.
 */
bool multi_device_cert_unpack(Multi_Device_Cert *_Nonnull cert, Bin_Unpack *_Nonnull bu);

/**
 * @brief Serialize a device list to bin_pack.
 */
bool multi_device_list_pack(const Multi_Device_List *_Nonnull list, Bin_Pack *_Nonnull bp);

/**
 * @brief Deserialize a device list from bin_unpack.
 */
bool multi_device_list_unpack(Multi_Device_List *_Nonnull list, Bin_Unpack *_Nonnull bu);

/**
 * @brief Generate a new device keypair.
 */
bool multi_device_generate_keypair(
    const Random *_Nonnull rng,
    uint8_t device_pubkey[CRYPTO_PUBLIC_KEY_SIZE],
    uint8_t device_seckey[CRYPTO_SECRET_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* C_TOXCORE_TOXCORE_MULTI_DEVICE_H */