#ifndef _BCRYPT_MACRO_TESTING_H_
#define _BCRYPT_MACRO_TESTING_H_

#include "bcrypt-parallel.h"

/* ========== Macro wrappers for testing ========== */

uint32_t f_asm(uint32_t x, const blf_ctx *state);

uint32_t blowfish_round_asm(uint32_t xl, uint32_t xr, const blf_ctx *state,
                            uint32_t n);

uint64_t reverse_bytes(uint64_t data);

void copy_ctext_asm(uint64_t *data, const char *ctext);

void load_salt_and_p(blf_ctx *state, uint8_t *salt);

uint32_t f_xmm(p_blf_ctx *state, uint32_t *bytes);

#endif