/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */
#include "multi_device.h"

#include <string.h>

#include "ccompat.h"

Multi_Device_List *multi_device_list_new(
    const Memory *mem,
    const uint8_t master_pubkey[CRYPTO_PUBLIC_KEY_SIZE])
{
    if (mem == nullptr || master_pubkey == nullptr) {
        return nullptr;
    }

    Multi_Device_List *list = (Multi_Device_List *)mem_alloc(mem, sizeof(Multi_Device_List));
    if (list == nullptr) {
        return nullptr;
    }

    list->mem = mem;
    list->num_devices = 0;
    memcpy(list->master_pubkey, master_pubkey, CRYPTO_PUBLIC_KEY_SIZE);

    return list;
}

void multi_device_list_free(Multi_Device_List *list)
{
    if (list == nullptr) {
        return;
    }
    mem_delete(list->mem, list);
}

bool multi_device_list_add(
    Multi_Device_List *list,
    const uint8_t master_seckey[CRYPTO_SECRET_KEY_SIZE],
    const uint8_t device_pubkey[CRYPTO_PUBLIC_KEY_SIZE],
    const uint8_t device_seckey[CRYPTO_SECRET_KEY_SIZE],
    const char *device_name, uint16_t name_length,
    const Mono_Time *mono_time,
    uint32_t ttl_seconds)
{
    if (list == nullptr || master_seckey == nullptr || device_pubkey == nullptr
            || device_name == nullptr || mono_time == nullptr) {
        return false;
    }

    if (list->num_devices >= MULTI_DEVICE_MAX_DEVICES) {
        return false;
    }

    if (name_length > MULTI_DEVICE_MAX_NAME_LENGTH) {
        return false;
    }

    // Check for duplicates
    if (multi_device_list_find(list, device_pubkey) >= 0) {
        return false;
    }

    Multi_Device_Cert *cert = &list->devices[list->num_devices];

    memcpy(cert->device_pubkey, device_pubkey, CRYPTO_PUBLIC_KEY_SIZE);
    cert->name_length = name_length;
    memcpy(cert->device_name, device_name, name_length);
    cert->device_name[name_length] = '\0';
    cert->created_timestamp = mono_time_get(mono_time);

    const uint32_t ttl = (ttl_seconds == 0)
        ? MULTI_DEVICE_DEFAULT_TTL_SECONDS : ttl_seconds;
    cert->expires_timestamp = mono_time_get(mono_time) + (uint64_t)ttl * 1000;

    // Build the data to sign
    uint8_t sign_data[MULTI_DEVICE_CERT_MAX_SIZE];
    uint8_t *ptr = sign_data;
    *ptr++ = MULTI_DEVICE_CERT_VERSION;
    memcpy(ptr, device_pubkey, CRYPTO_PUBLIC_KEY_SIZE); ptr += CRYPTO_PUBLIC_KEY_SIZE;
    *ptr++ = (uint8_t)(name_length & 0xFF);
    *ptr++ = (uint8_t)(name_length >> 8);
    memcpy(ptr, device_name, name_length); ptr += name_length;
    memcpy(ptr, &cert->created_timestamp, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    memcpy(ptr, &cert->expires_timestamp, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    const size_t sign_len = ptr - sign_data;

    // Sign with master key using Ed25519
    (void)device_seckey;  // Not used — cert is signed by master, not device
    if (!crypto_signature_create(cert->signature, sign_data, sign_len, master_seckey)) {
        return false;
    }

    ++list->num_devices;
    return true;
}

bool multi_device_list_remove(
    Multi_Device_List *list,
    const uint8_t device_pubkey[CRYPTO_PUBLIC_KEY_SIZE])
{
    const int idx = multi_device_list_find(list, device_pubkey);
    if (idx < 0) {
        return false;
    }

    // Shift remaining devices down
    for (uint8_t i = (uint8_t)idx; i < list->num_devices - 1; ++i) {
        list->devices[i] = list->devices[i + 1];
    }

    --list->num_devices;
    return true;
}

int multi_device_list_find(
    const Multi_Device_List *list,
    const uint8_t device_pubkey[CRYPTO_PUBLIC_KEY_SIZE])
{
    if (list == nullptr || device_pubkey == nullptr) {
        return -1;
    }

    for (uint8_t i = 0; i < list->num_devices; ++i) {
        if (memcmp(list->devices[i].device_pubkey, device_pubkey, CRYPTO_PUBLIC_KEY_SIZE) == 0) {
            return (int)i;
        }
    }

    return -1;
}

uint8_t multi_device_list_verify(const Multi_Device_List *list)
{
    if (list == nullptr) {
        return 0;
    }

    uint8_t valid_count = 0;

    for (uint8_t i = 0; i < list->num_devices; ++i) {
        const Multi_Device_Cert *cert = &list->devices[i];

        // Rebuild signed data
        uint8_t sign_data[MULTI_DEVICE_CERT_MAX_SIZE];
        uint8_t *ptr = sign_data;
        *ptr++ = MULTI_DEVICE_CERT_VERSION;
        memcpy(ptr, cert->device_pubkey, CRYPTO_PUBLIC_KEY_SIZE); ptr += CRYPTO_PUBLIC_KEY_SIZE;
        *ptr++ = (uint8_t)(cert->name_length & 0xFF);
        *ptr++ = (uint8_t)(cert->name_length >> 8);
        memcpy(ptr, cert->device_name, cert->name_length); ptr += cert->name_length;
        memcpy(ptr, &cert->created_timestamp, sizeof(uint64_t)); ptr += sizeof(uint64_t);
        memcpy(ptr, &cert->expires_timestamp, sizeof(uint64_t)); ptr += sizeof(uint64_t);
        const size_t sign_len = ptr - sign_data;

        if (crypto_signature_verify(cert->signature, sign_data, sign_len, list->master_pubkey)) {
            ++valid_count;
        }
    }

    return valid_count;
}

uint8_t multi_device_list_prune_expired(
    Multi_Device_List *list,
    const Mono_Time *mono_time)
{
    if (list == nullptr || mono_time == nullptr) {
        return 0;
    }

    const uint64_t now = mono_time_get(mono_time);
    uint8_t removed = 0;

    // Work backwards to avoid index issues when removing
    for (int i = (int)list->num_devices - 1; i >= 0; --i) {
        if (list->devices[i].expires_timestamp != 0
                && list->devices[i].expires_timestamp <= now) {
            multi_device_list_remove(list, list->devices[i].device_pubkey);
            ++removed;
        }
    }

    return removed;
}

bool multi_device_cert_pack(const Multi_Device_Cert *cert, Bin_Pack *bp)
{
    return bin_pack_array(bp, 6)
           && bin_pack_bin(bp, cert->device_pubkey, CRYPTO_PUBLIC_KEY_SIZE)
           && bin_pack_bin(bp, (const uint8_t *)cert->device_name, cert->name_length)
           && bin_pack_u64(bp, cert->created_timestamp)
           && bin_pack_u64(bp, cert->expires_timestamp)
           && bin_pack_bin(bp, cert->signature, CRYPTO_SIGNATURE_SIZE);
}

bool multi_device_cert_unpack(Multi_Device_Cert *cert, Bin_Unpack *bu)
{
    if (!bin_unpack_array_fixed(bu, 6, nullptr)) {
        return false;
    }

    return bin_unpack_bin_fixed(bu, cert->device_pubkey, CRYPTO_PUBLIC_KEY_SIZE)
           && bin_unpack_bin(bu, (uint8_t **)&cert->device_name, &cert->name_length)
           && bin_unpack_u64(bu, &cert->created_timestamp)
           && bin_unpack_u64(bu, &cert->expires_timestamp)
           && bin_unpack_bin_fixed(bu, cert->signature, CRYPTO_SIGNATURE_SIZE);
}

bool multi_device_list_pack(const Multi_Device_List *list, Bin_Pack *bp)
{
    if (!bin_pack_array(bp, 2 + list->num_devices)) {
        return false;
    }

    if (!bin_pack_bin(bp, list->master_pubkey, CRYPTO_PUBLIC_KEY_SIZE)) {
        return false;
    }

    if (!bin_pack_u8(bp, list->num_devices)) {
        return false;
    }

    for (uint8_t i = 0; i < list->num_devices; ++i) {
        if (!multi_device_cert_pack(&list->devices[i], bp)) {
            return false;
        }
    }

    return true;
}

bool multi_device_list_unpack(Multi_Device_List *list, Bin_Unpack *bu)
{
    uint32_t array_size;
    if (!bin_unpack_array(bu, &array_size)) {
        return false;
    }

    // master_pubkey
    if (!bin_unpack_bin_fixed(bu, list->master_pubkey, CRYPTO_PUBLIC_KEY_SIZE)) {
        return false;
    }

    // num_devices
    uint8_t num_devices;
    if (!bin_unpack_u8(bu, &num_devices)) {
        return false;
    }

    if (num_devices > MULTI_DEVICE_MAX_DEVICES) {
        return false;
    }

    list->num_devices = 0;

    for (uint8_t i = 0; i < num_devices; ++i) {
        if (!multi_device_cert_unpack(&list->devices[i], bu)) {
            return false;
        }
        ++list->num_devices;
    }

    return true;
}

bool multi_device_generate_keypair(
    const Random *rng,
    uint8_t device_pubkey[CRYPTO_PUBLIC_KEY_SIZE],
    uint8_t device_seckey[CRYPTO_SECRET_KEY_SIZE])
{
    return crypto_new_keypair(rng, device_pubkey, device_seckey) == 0;
}