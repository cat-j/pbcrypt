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

#ifndef _PARALLEL_TEST_WRAPPERS_H_
#define _PARALLEL_TEST_WRAPPERS_H_

#include "bcrypt-common.h"

void blowfish_expand_state_parallel_wrapper(p_blf_ctx *state, const uint8_t *salt,
                                            const char *keys, uint16_t keybytes);

void blowfish_expand_0_state_parallel_wrapper(p_blf_ctx *state,
                                              const char *keys, uint16_t keybytes);

void blowfish_expand_0_state_salt_parallel_wrapper(p_blf_ctx *state, const uint8_t *salt);


#endif