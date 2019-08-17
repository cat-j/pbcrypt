#ifndef _LOADED_P_TEST_WRAPPERS_H_
#define _LOADED_P_TEST_WRAPPERS_H

#include "bcrypt.h"

void blowfish_expand_state_wrapper(blf_ctx *state, const char *salt,
                                   const char *key, uint16_t keybytes);

void blowfish_expand_0_state_wrapper(blf_ctx *state, const char *salt,
                                     const char *key, uint64_t keybytes);

#endif