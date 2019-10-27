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

#include <stdlib.h>

#include "bcrypt-common.h"
#include "bcrypt-parallel-double.h"
#include "print.h"

pd_blf_ctx *get_aligned_pd_state() {
    pd_blf_ctx *pd_state;
    posix_memalign((void**) &pd_state, 32, sizeof(pd_blf_ctx));
    return pd_state;
}

int hash_match_parallel_double(const uint8_t *hashes, const uint8_t *target) {
    size_t k;

    for (size_t i = 0; i < DWORDS_PER_YMM; ++i) {
        k = 0;

        for (size_t j = 0; j < BCRYPT_HASH_BYTES - 3; ++j) {
            if (hashes[i*BYTES_PER_DATA_BLOCK + k] != target[j])
                break;

            if (j%BYTES_PER_DATA_BLOCK != 3) {
                ++k;
            } else {
                k += 29; // move to next data block
            }

            if (j == BCRYPT_HASH_BYTES - 4)
                return i; // ith hash matches!
        }
    }

    // None of the hashes matches
    return -1;
}