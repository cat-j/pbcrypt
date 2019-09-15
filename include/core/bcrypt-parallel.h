#ifndef _BCRYPT_PARALLEL_H_
#define _BCRYPT_PARALLEL_H_

#include <stdint.h>

#include "bcrypt-common.h"

/* ========== Parallelised functions ========== */

void blowfish_parallelise_state(p_blf_ctx *state, blf_ctx *src);

void blowfish_init_state_parallel(p_blf_ctx *state, p_blf_ctx *src);

void blowfish_expand_state_parallel(p_blf_ctx *state, const char *salt,
                                    const char *keys, uint64_t keybytes);

void blowfish_expand_0_state_parallel(p_blf_ctx *state, const char *keys,
                                      uint64_t keybytes);

void blowfish_expand_0_state_salt_parallel(p_blf_ctx *state, const char *salt);

void bcrypt_hashpass_parallel(p_blf_ctx *state, const char *salt,
                              const char *keys, uint16_t keybytes,
                              uint8_t *hashes, uint64_t rounds);

#endif