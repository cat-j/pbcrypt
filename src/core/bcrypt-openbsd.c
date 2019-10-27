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

#include "bcrypt.h"
#include "openbsd.h"

/*
 * Just a wrapper for measuring the OpenBSD implementation's
 * performance without having to write a new cracker.
 * State must be already initialised.
 */
void bcrypt_hashpass(blf_ctx *state, const uint8_t *salt,
                     const char *key, uint16_t keybytes,
                     uint8_t *hash, uint64_t rounds)
{
    uint32_t i, k;
    uint16_t j;
    uint8_t salt_len = BCRYPT_MAXSALT;
    uint8_t ciphertext[4 * BCRYPT_WORDS] = "OrpheanBeholderScryDoubt";
    uint32_t cdata[BCRYPT_WORDS];

    Blowfish_initstate(state);
    Blowfish_expandstate(state, salt, salt_len,
        (uint8_t *) key, keybytes);

    for (k = 0; k < rounds; k++) {
        Blowfish_expand0state(state, (uint8_t *) key, keybytes);
        Blowfish_expand0state(state, salt, salt_len);
    }

    j = 0;
    for (i = 0; i < BCRYPT_WORDS; i++)
        cdata[i] = Blowfish_stream2word(ciphertext, 4 * BCRYPT_WORDS, &j);

    for (k = 0; k < 64; k++)
        blf_enc(state, cdata, BCRYPT_WORDS / 2);

    for (i = 0; i < BCRYPT_WORDS; i++) {
        hash[4 * i + 3] = cdata[i] & 0xff;
        cdata[i] = cdata[i] >> 8;
        hash[4 * i + 2] = cdata[i] & 0xff;
        cdata[i] = cdata[i] >> 8;
        hash[4 * i + 1] = cdata[i] & 0xff;
        cdata[i] = cdata[i] >> 8;
        hash[4 * i + 0] = cdata[i] & 0xff;
    }
}

/*
 * Wrapper for measuring OpenBSD performance.
 */
void blowfish_init_state_asm(blf_ctx *state) {
    Blowfish_initstate(state);
}

int variant = 9;