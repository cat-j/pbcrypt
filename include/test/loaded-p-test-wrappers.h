#ifndef _LOADED_P_TEST_WRAPPERS_H_
#define _LOADED_P_TEST_WRAPPERS_H

#include "bcrypt.h"

/*
 * Test wrappers for loaded P-array variant.
 * The reason behind these is that the ASM key schedule functions
 * require the P-array to be previously loaded into some YMM regs
 * and there's no non-tedious way to enforce that these are preserved
 * from within C or through compilation flags.
 */

void blowfish_expand_state_wrapper(blf_ctx *state, const uint8_t *salt,
                                   const char *key, uint16_t keybytes);

void blowfish_expand_0_state_wrapper(blf_ctx *state, const uint8_t *salt,
                                     const char *key, uint16_t keybytes);

void blowfish_expand_0_state_salt_wrapper(blf_ctx *state, const uint8_t *salt,
                                          const char *key, uint16_t keybytes);

#endif