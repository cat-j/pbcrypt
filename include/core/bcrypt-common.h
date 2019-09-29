#ifndef _BCRYPT_COMMON_H_
#define _BCRYPT_COMMON_H_

#include <stdint.h>

/* ========== Constants ========== */

#define BCRYPT_MIN_LOG_ROUNDS    4
#define BCRYPT_MAX_LOG_ROUNDS    32
#define BCRYPT_ENCODED_SALT_SIZE 22
#define BCRYPT_ENCODED_HASH_SIZE 31
#define BCRYPT_RECORD_SIZE       60

#define S_BOX_LENGTH      256
#define P_ARRAY_LENGTH    18
#define BCRYPT_WORDS      6
#define BCRYPT_SALT_BYTES 16
#define BCRYPT_HASH_BYTES 24

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

/* ========== Variables ========== */

extern int variant; // unrolled loops, P-array in YMM registers, etc

#endif