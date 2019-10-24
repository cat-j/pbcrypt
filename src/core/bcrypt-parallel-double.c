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