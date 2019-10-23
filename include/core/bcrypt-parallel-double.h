#ifndef _BCRYPT_PARALLEL_DOUBLE_H_
#define _BCRYPT_PARALLEL_DOUBLE_H_

#include <stdint.h>

#include "bcrypt-common.h"

/* ========== Useful constants ========== */

#define DWORDS_PER_YMM 8

/* ========== Parallelised functions ========== */

/*
 * Derive a parallel Blowfish state representing
 * eight identical copies of the source state,
 * where each nth four-dword block contains the nth elements
 * from eight single-data states (either S elements
 * or P elements).
 */
void blowfish_parallelise_state_double(pd_blf_ctx *state, const blf_ctx *src);

/*
 * For parallel key schedule.
 * Copy source state to destination state.
 */
void blowfish_init_state_parallel_double(pd_blf_ctx *dst, pd_blf_ctx *src);

/*
 * For parallel key schedule.
 * Encrypt eight copies of state boxes and eight copies of P-array
 * with the same salt and eight consecutive keys of the same length.
 * When finished, each nth block of eight dwords in the parallel state
 * should contain the nth elements from eight single-data states,
 * each jth of which should in turn be encrypted with the jth key.
 * Keys must be null-terminated.
 */
void blowfish_expand_state_parallel_double(pd_blf_ctx *state, const uint8_t *salt,
                                           const char *keys, uint16_t keybytes);

/*
 * For parallel key schedule.
 * Encrypt eight copies of state boxes and eight copies of P-array
 * with eight consecutive keys of the same length.
 * When finished, each nth block of eight dwords in the parallel state
 * should contain the nth elements from eight single-data states,
 * each jth of which should in turn be encrypted with the jth key.
 * Keys must be null-terminated.
 */
void blowfish_expand_0_state_parallel_double(pd_blf_ctx *state, const char *keys,
                                             uint16_t keybytes);

/*
 * For parallel key schedule.
 * Encrypt eight copies of state boxes and eight copies of P-array
 * with the same salt.
 * Optimised for working with 128-bit data,
 * i.e. each 32-bit block is broadcast once into a 128-bit register
 * and no further memory accesses are needed for salt data.
 */
void blowfish_expand_0_state_salt_parallel_double(pd_blf_ctx *state,
                                                  const uint8_t *salt);

/*
 * Hash eight passwords (keys) and store results in hashes.
 * Variable rounds corresponds to actual number of rounds,
 * not log.
 * When finished, each nth block of eight dwords in hashes
 * should contain the nth elements from eight single-data hashes.
 * Keys must be null-terminated.
 */
void bcrypt_hashpass_parallel_double(pd_blf_ctx *state, const uint8_t *salt,
                                     const char *keys, uint16_t keybytes,
                                     uint8_t *hashes, uint64_t rounds);

/*
 * Return a 32-bit aligned pointer to an uninitialised
 * double parallel Blowfish state.
 */
pd_blf_ctx *get_aligned_pd_state();

/*
 * Compare the first 21 bytes of a hash against
 * the first 21 bytes of eight parallel hashes.
 * Designed for cracking.
 * Return matching hash number (0 to 7) if matched
 * and -1 otherwise.
 */
int hash_match_parallel_double(const uint8_t *hashes, const uint8_t *target);

#endif