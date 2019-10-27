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

#ifndef _OPENBSD_H_
#define _OPENBSD_H_

#include <stdint.h>
#include <stdlib.h>

#include "bcrypt.h"

#define BCRYPT_MAXSALT 16     /* Precomputation is just so nice */

/*
 * Code from OpenBSD implementation of bcrypt,
 * isolated for easy testing and experiments.
 */

void Blowfish_initstate(blf_ctx *c);

void Blowfish_expandstate(blf_ctx *c, const uint8_t *data, uint16_t databytes,
    const uint8_t *key, uint16_t keybytes);

void Blowfish_expand0state(blf_ctx *c, const uint8_t *key, uint16_t keybytes);

void Blowfish_expand0statesalt(blf_ctx *c, const uint8_t *key, uint16_t keybytes);

void Blowfish_encipher(const blf_ctx *c, uint32_t *xl, uint32_t *xr);

void blf_enc(const blf_ctx *c, uint32_t *data, uint16_t blocks);

uint32_t Blowfish_stream2word(const uint8_t *data, uint16_t databytes,
    uint16_t *current);

uint32_t f_wrapper(uint32_t x, const blf_ctx *state);

uint32_t blfrnd_wrapper(const blf_ctx *state, uint32_t xl, uint32_t xr,
                        uint32_t n);

void copy_ctext_openbsd(uint32_t *cdata, const char *ctext, size_t scale);

void bcrypt_hashpass_openbsd(blf_ctx *state, const char *key,
                             const char *salt, uint64_t rounds,
                             uint8_t *hash);

#endif