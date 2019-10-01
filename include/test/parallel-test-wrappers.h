#ifndef _PARALLEL_TEST_WRAPPERS_H_
#define _PARALLEL_TEST_WRAPPERS_H_

#include "bcrypt-common.h"

void blowfish_expand_state_parallel_wrapper(p_blf_ctx *state, const uint8_t *salt,
                                            const char *keys, uint16_t keybytes);

void blowfish_expand_0_state_salt_parallel_wrapper(p_blf_ctx *state, const uint8_t *salt);


#endif