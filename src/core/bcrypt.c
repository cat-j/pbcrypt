#include <ctype.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "bcrypt.h"
#include "print.h"

// #define BCRYPT_MAX_KEY_BYTES 

int hash_match(const uint8_t *hash1, const uint8_t *hash2) {
    for (size_t i = 0; i < BCRYPT_HASH_BYTES - 3; ++i) {
        if (hash1[i] != hash2[i])
            return 0;
    }

    return 1;
}

// TODO: return the whole record, not just the hash
char *bcrypt(const char *salt, const char *key, uint16_t keybytes,
             uint64_t rounds)
{
    uint8_t hash[BCRYPT_HASH_BYTES];
    int status;

    if ( (status = bcrypt_asm_wrapper(salt, hash, key, keybytes, rounds)) ) {
        fprintf(stderr, RED("Error executing bcrypt. Code: 0x%x\n"), status);
        return 0;
    }

    char *encoded = malloc(BCRYPT_ENCODED_HASH_SIZE+2);
    encode_base64(encoded, hash, BCRYPT_HASH_BYTES);

    return encoded;
}

blf_ctx *get_aligned_state() {
    blf_ctx *state;
    posix_memalign((void**) &state, 32, sizeof(blf_ctx));
    return state;
}