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

#ifndef _BCRYPT_COMMON_H_
#define _BCRYPT_COMMON_H_

#include <stdint.h>

/* ========== Constants ========== */

#define BCRYPT_MIN_ROUNDS_LOG    4
#define BCRYPT_MAX_ROUNDS_LOG    32
#define BCRYPT_ENCODED_SALT_SIZE 22
#define BCRYPT_ENCODED_HASH_SIZE 31
#define BCRYPT_RECORD_SIZE       60

#define S_BOX_LENGTH      256
#define P_ARRAY_LENGTH    18
#define BCRYPT_WORDS      6
#define BCRYPT_SALT_BYTES 16
#define BCRYPT_HASH_BYTES 24

#define BYTES_PER_DATA_BLOCK 4

/* ========== Types ========== */

/* Blowfish context - taken from OpenBSD source code */
typedef struct BlowfishContext {
    uint32_t S[4][256];    /* S-Boxes */
    uint32_t P[18];        /* Subkeys */
} blf_ctx;

/* Blowfish context with 4 copies of each element */
typedef struct ParallelBlowfishContext {
    uint32_t S[4][1024];
    uint32_t P[72];
} p_blf_ctx;

// Defining a new struct isn't great but it's better
// than having to modify existing code so it accesses
// S and P via pointers.

/* Blowfish context with 8 copies of each element */
typedef struct ParallelDoubleBlowfishContext {
    uint32_t S[4][2048];
    uint32_t P[144];
} pd_blf_ctx;

/* ========== Variables ========== */

extern int variant; // unrolled loops, P-array in YMM registers, etc

#endif