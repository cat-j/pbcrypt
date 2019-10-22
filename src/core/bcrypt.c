#include <ctype.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "bcrypt.h"
#include "bcrypt-common.h"
#include "cracker-errors.h"
#include "print.h"

int hash_match(const uint8_t *hash1, const uint8_t *hash2) {
    for (size_t i = 0; i < BCRYPT_HASH_BYTES - 3; ++i) {
        if (hash1[i] != hash2[i])
            return 0;
    }

    return 1;
}

char *bcrypt(const uint8_t *salt, const char *key, uint16_t keybytes,
             uint8_t rounds_log)
{
    uint8_t hash[BCRYPT_HASH_BYTES];
    int status;
    char version = 'b'; // TODO: accept other versions
    uint64_t rounds = 1L << rounds_log;

    if ( (status = bcrypt_asm_wrapper(salt, hash, key, keybytes, rounds)) ) {
        fprintf(stderr, BOLD_RED("Error executing bcrypt. Code: 0x%x\n"), status);
        return 0;
    }

    char *record = malloc(BCRYPT_RECORD_SIZE+1);
    char *ptr = record;

    sprintf(ptr, "$2%c$", version);
    ptr += 4;

    sprintf(ptr, "%02u$", rounds_log);
    ptr += 3;

    encode_base64(ptr, salt, BCRYPT_SALT_BYTES);
    ptr += BCRYPT_ENCODED_SALT_SIZE;

    encode_base64(ptr, hash, BCRYPT_ENCODED_HASH_SIZE+2);
    ptr += BCRYPT_ENCODED_HASH_SIZE;

    *ptr = 0; // null terminate

    return record;
}

// TODO: accept different bcrypt versions
int bcrypt_asm_wrapper(const uint8_t *salt, uint8_t *hash, const char *key,
                       uint16_t keybytes, uint64_t rounds)
{
    if (!salt)
        return ERR_BAD_SALT;
    
    if (!key)
        return ERR_BAD_KEY;

    if (!hash)
        return ERR_BAD_HASH;

    if (strlen((char *) salt) != BCRYPT_SALT_BYTES)
        return ERR_SALT_LEN;
    
    blf_ctx *state = malloc(sizeof(blf_ctx));
    bcrypt_hashpass(state, salt, key, keybytes, hash, rounds);
    free(state);

    return 0;
}

blf_ctx *get_aligned_state(int variant) {
    blf_ctx *state;

    // Variants 0 to 4 are not necessarily cache-aligned
    if (variant < 5) {
        posix_memalign((void**) &state, 32, sizeof(blf_ctx));
    } else {
        posix_memalign((void**) &state, 512, sizeof(blf_ctx));
    }

    return state;
}