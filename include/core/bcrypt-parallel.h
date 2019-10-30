/*
 * pbcrypt: parallel bcrypt for password cracking
 * Copyright (C) 2019  Catalina Juarros <https://github.com/cat-j>
 *
 * This file is part of pbcrypt.
 * 
 * pbcrypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * 
 * pbcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with pbcrypt.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef _BCRYPT_PARALLEL_H_
#define _BCRYPT_PARALLEL_H_

#include <stdint.h>

#include "bcrypt-common.h"

/* ========== Useful constants ========== */

#define DWORDS_PER_XMM 4

/* ========== Parallelised functions ========== */

/*
 * Derive a parallel Blowfish state representing
 * four identical copies of the source state,
 * where each nth four-dword block contains the nth elements
 * from four single-data states (either S elements
 * or P elements).
 */
void blowfish_parallelise_state(p_blf_ctx *state, const blf_ctx *src);

/*
 * For parallel key schedule.
 * Copy source state to destination state.
 */
void blowfish_init_state_parallel(p_blf_ctx *dst, p_blf_ctx *src);

/*
 * For parallel key schedule.
 * Encrypt four copies of state boxes and four copies of P-array
 * with the same salt and four consecutive keys of the same length.
 * When finished, each nth block of four dwords in the parallel state
 * should contain the nth elements from four single-data states,
 * each jth of which should in turn be encrypted with the jth key.
 * Keys must be null-terminated.
 */
void blowfish_expand_state_parallel(p_blf_ctx *state, const uint8_t *salt,
                                    const char *keys, uint16_t keybytes);

/*
 * For parallel key schedule.
 * Encrypt four copies of state boxes and four copies of P-array
 * with four consecutive keys of the same length.
 * When finished, each nth block of four dwords in the parallel state
 * should contain the nth elements from four single-data states,
 * each jth of which should in turn be encrypted with the jth key.
 * Keys must be null-terminated.
 */
void blowfish_expand_0_state_parallel(p_blf_ctx *state, const char *keys,
                                      uint16_t keybytes);

/*
 * For parallel key schedule.
 * Encrypt four copies of state boxes and four copies of P-array
 * with the same salt.
 * Optimised for working with 128-bit data,
 * i.e. each 32-bit block is broadcast once into a 128-bit register
 * and no further memory accesses are needed for salt data.
 */
void blowfish_expand_0_state_salt_parallel(p_blf_ctx *state, const uint8_t *salt);

/*
 * Hash four passwords (keys) and store results in hashes.
 * Variable rounds corresponds to actual number of rounds,
 * not log.
 * When finished, each nth block of four dwords in hashes
 * should contain the nth elements from four single-data hashes.
 * Keys must be null-terminated.
 */
void bcrypt_hashpass_parallel(p_blf_ctx *state, const uint8_t *salt,
                              const char *keys, uint16_t keybytes,
                              uint8_t *hashes, uint64_t rounds);

/*
 * Return a 32-bit aligned pointer to an uninitialised
 * parallel Blowfish state.
 */
p_blf_ctx *get_aligned_p_state();

/*
 * Compare the first 21 bytes of a hash against
 * the first 21 bytes of four parallel hashes.
 * Designed for cracking.
 * Return matching hash number (0 to 3) if matched
 * and -1 otherwise.
 */
int hash_match_parallel(const uint8_t *hashes, const uint8_t *target);

#endif