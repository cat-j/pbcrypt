#ifndef _BCRYPT_PARALLEL_H_
#define _BCRYPT_PARALLEL_H_

#include <stdint.h>

#include "bcrypt-common.h"

/* Blowfish context with 4 copies of each element */
typedef struct ParallelBlowfishContext {
    uint32_t S[4][1024];
    uint32_t P[72];
} p_blf_ctx;

/* ========== Parallelised functions ========== */

void blowfish_parallelise_state(p_blf_ctx *state, blf_ctx *src);

#endif