/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

/**
 * @brief Hashcash-style proof-of-work for anti-spam.
 *
 * Replaces the static nospam field with a dynamic difficulty-based POW
 * for friend requests. Sender computes POW; receiver verifies in O(1).
 *
 * Algorithm: find a 64-bit nonce such that BLAKE2b(pubkey || nonce || difficulty)
 * has at least `difficulty` leading zero bits. Verification is a single hash.
 *
 * Difficulty 0 = no POW (backward compatible with nospam).
 * Default difficulty = 0 (off).
 * Recommended maximum = 24 bits (~1 million hashes, <1ms).
 */
#ifndef C_TOXCORE_TOXCORE_POW_H
#define C_TOXCORE_TOXCORE_POW_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"
#include "crypto_core.h"
#include "rng.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum POW difficulty (bits). 24 takes ~1ms on modern CPU. */
#define POW_MAX_DIFFICULTY 24

/** Size of the POW nonce in bytes. */
#define POW_NONCE_SIZE 8

/** Size of the POW output hash (BLAKE2b-256 = 32 bytes). */
#define POW_HASH_SIZE 32

/**
 * @brief Compute a proof-of-work nonce for the given public key and difficulty.
 *
 * Finds a nonce such that BLAKE2b(pubkey || nonce || difficulty) has at least
 * `difficulty` leading zero bits.
 *
 * @param rng Random number generator for initial nonce.
 * @param pubkey The public key to bind the POW to (32 bytes).
 * @param difficulty Number of leading zero bits required (0..POW_MAX_DIFFICULTY).
 * @param nonce_out Output: the 8-byte nonce that satisfies the POW.
 * @return true on success.
 */
bool pow_compute(
    const Random *_Nonnull rng,
    const uint8_t pubkey[CRYPTO_PUBLIC_KEY_SIZE],
    uint8_t difficulty,
    uint8_t nonce_out[POW_NONCE_SIZE]);

/**
 * @brief Verify a proof-of-work nonce.
 *
 * Checks that BLAKE2b(pubkey || nonce || difficulty) has at least
 * `difficulty` leading zero bits.
 *
 * @return true if the POW is valid.
 */
bool pow_verify(
    const uint8_t pubkey[CRYPTO_PUBLIC_KEY_SIZE],
    const uint8_t nonce[POW_NONCE_SIZE],
    uint8_t difficulty);

#ifdef __cplusplus
}
#endif

#endif /* C_TOXCORE_TOXCORE_POW_H */