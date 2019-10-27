/*
 * pbcrypt: parallel bcrypt for password cracking
 * Copyright (C) 2019  Catalina Juarros (catalinajuarros@protonmail.com)
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

#ifndef _BCRYPT_MACRO_TESTING_H_
#define _BCRYPT_MACRO_TESTING_H_

#include "bcrypt-parallel.h"

/* ========== Macro wrappers for testing ========== */

uint32_t f_asm(uint32_t x, const blf_ctx *state);

uint32_t blowfish_round_asm(uint32_t xl, uint32_t xr, const blf_ctx *state,
                            uint32_t n);

uint64_t reverse_bytes(uint64_t data);

void copy_ctext_asm(uint64_t *data, const uint8_t *ctext);

void copy_ctext_xmm(uint64_t *data, const uint8_t *ctext);

void copy_ctext_ymm(uint64_t *data, const uint8_t *ctext);

void load_salt_and_p(blf_ctx *state, uint8_t *salt);

void f_xmm(p_blf_ctx *state, uint32_t *bytes);

void f_ymm(pd_blf_ctx *state, uint32_t *bytes);

void blowfish_round_xmm(const p_blf_ctx *state, uint32_t *xl, uint32_t *xr,
                        uint32_t n);

void blowfish_round_ymm(const pd_blf_ctx *state, uint32_t *xl, uint32_t *xr,
                        uint32_t n);

#endif