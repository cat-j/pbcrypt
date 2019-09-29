#include <stdlib.h>

#include "bcrypt-parallel.h"

p_blf_ctx *get_aligned_p_state() {
    p_blf_ctx *p_state;
    posix_memalign((void**) &p_state, 32, sizeof(p_blf_ctx));
    return p_state;
}

int hash_match_parallel(const uint8_t *hashes, const uint8_t *target) {
    uint8_t *current = hashes;

    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < BCRYPT_HASH_BYTES - 3; ++j) {
            if (current[j] != target[j])
                break;
            // If j reached the last byte and the loop didn't break,
            // the ith hash matches!
            if (j == BCRYPT_HASH_BYTES - 4)
                return i;
        }
    }

    // None of the hashes matches
    return -1;
}