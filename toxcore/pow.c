/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */
#include "pow.h"

#include <string.h>

#include <sodium.h>

#include "ccompat.h"

bool pow_compute(
    const Random *rng,
    const uint8_t pubkey[CRYPTO_PUBLIC_KEY_SIZE],
    uint8_t difficulty,
    uint8_t nonce_out[POW_NONCE_SIZE])
{
    if (rng == nullptr || pubkey == nullptr || nonce_out == nullptr) {
        return false;
    }

    if (difficulty > POW_MAX_DIFFICULTY) {
        difficulty = POW_MAX_DIFFICULTY;
    }

    // Difficulty 0 = no POW needed
    if (difficulty == 0) {
        memset(nonce_out, 0, POW_NONCE_SIZE);
        return true;
    }

    // Start with a random nonce
    random_bytes(rng, nonce_out, POW_NONCE_SIZE);
    uint64_t nonce;
    memcpy(&nonce, nonce_out, sizeof(nonce));

    crypto_generichash_state state;
    uint8_t hash[POW_HASH_SIZE];

    const uint64_t max_attempts = UINT64_C(1) << (difficulty + 5); // limit to prevent infinite loop
    for (uint64_t attempt = 0; attempt < max_attempts; ++attempt) {
        // Hash: BLAKE2b(pubkey || nonce || difficulty)
        crypto_generichash_init(&state, nullptr, 0, POW_HASH_SIZE);
        crypto_generichash_update(&state, pubkey, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(nonce_out, &nonce, sizeof(nonce));
        crypto_generichash_update(&state, nonce_out, POW_NONCE_SIZE);
        uint8_t diff_byte = difficulty;
        crypto_generichash_update(&state, &diff_byte, 1);
        crypto_generichash_final(&state, hash, POW_HASH_SIZE);

        // Check leading zero bits
        if (pow_verify(pubkey, nonce_out, difficulty)) {
            return true;
        }

        ++nonce;
    }

    return false;  // Should be extremely rare
}

bool pow_verify(
    const uint8_t pubkey[CRYPTO_PUBLIC_KEY_SIZE],
    const uint8_t nonce[POW_NONCE_SIZE],
    uint8_t difficulty)
{
    if (pubkey == nullptr || nonce == nullptr) {
        return false;
    }

    if (difficulty == 0) {
        return true;  // No POW required
    }

    if (difficulty > POW_MAX_DIFFICULTY) {
        return false;
    }

    crypto_generichash_state state;
    uint8_t hash[POW_HASH_SIZE];

    crypto_generichash_init(&state, nullptr, 0, POW_HASH_SIZE);
    crypto_generichash_update(&state, pubkey, CRYPTO_PUBLIC_KEY_SIZE);
    crypto_generichash_update(&state, nonce, POW_NONCE_SIZE);
    uint8_t diff_byte = difficulty;
    crypto_generichash_update(&state, &diff_byte, 1);
    crypto_generichash_final(&state, hash, POW_HASH_SIZE);

    // Count leading zero bits
    uint8_t zero_bits = 0;
    for (uint8_t i = 0; i < POW_HASH_SIZE; ++i) {
        if (hash[i] == 0) {
            zero_bits += 8;
        } else {
            // Count leading zeros in this byte
            uint8_t mask = 0x80;
            while (mask != 0 && (hash[i] & mask) == 0) {
                ++zero_bits;
                mask >>= 1;
            }
            break;
        }
    }

    return zero_bits >= difficulty;
}