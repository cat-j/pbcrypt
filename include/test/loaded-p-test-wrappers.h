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