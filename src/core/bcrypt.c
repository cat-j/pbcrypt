#include <ctype.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "bcrypt.h"

// #define BCRYPT_MAX_KEY_BYTES 

#define ERR_RECORD_LEN    0x10010
#define ERR_RECORD_FORMAT 0x10020
#define ERR_VERSION       0x10030
#define ERR_ROUNDS        0x10040
#define ERR_BASE64        0x10050

#define ERR_BAD_SALT      0x30010
#define ERR_BAD_KEY       0x30020
#define ERR_BAD_HASH      0x30030
#define ERR_SALT_LEN      0x30040

int is_valid_version(char c) {
    return c == 'a' || c == 'b' || c == 'x' || c == 'y';
}

int get_record_data(char *record, uint8_t *ciphertext,
                    uint8_t *salt, uint64_t *rounds)
{
    uint8_t log_rounds;

    if (strlen(record) != BCRYPT_RECORD_SIZE)
        return ERR_RECORD_LEN;

    if (record[0] != '$' || record[3] != '$')
        return ERR_RECORD_FORMAT;
    record++;

    if (record[0] != '2' || !is_valid_version(record[1]))
        return ERR_VERSION;
    record += 3;

    if (!isdigit((unsigned char)record[0]) ||
        !isdigit((unsigned char)record[1]) || record[2] != '$')
        return ERR_ROUNDS;

    // Parse rounds
    log_rounds = (record[1] - '0') + ((record[0] - '0') * 10);
    if (log_rounds < BCRYPT_MIN_LOG_ROUNDS || log_rounds > BCRYPT_MAX_LOG_ROUNDS)
        return ERR_ROUNDS;
    record += 3;
    
    *rounds = 1U << log_rounds;

    // Decode salt
    if (decode_base64(salt, BCRYPT_SALT_BYTES, record))
        return ERR_BASE64;
    record += BCRYPT_ENCODED_SALT_SIZE;

    // Decode ciphertext
    if (decode_base64(ciphertext, 21, record))
        return ERR_BASE64;

    return 0;
}

/* Compare first 21 bytes of two hashes.
 * Designed for cracking.
 */
int hash_match(const uint8_t *hash1, const uint8_t *hash2) {
    for (size_t i = 0; i < BCRYPT_HASH_BYTES - 3; ++i) {
        if (hash1[i] != hash2[i])
            return 0;
    }

    return 1;
}

// TODO: accept different bcrypt versions#
int bcrypt_asm_wrapper(const char *salt, uint8_t *hash, const char *key,
                       uint16_t keybytes, uint64_t rounds)
{
    if (!salt)
        return ERR_BAD_SALT;
    
    if (!key)
        return ERR_BAD_KEY;

    if (!hash)
        return ERR_BAD_HASH;

    if (strlen(salt) != BCRYPT_SALT_BYTES)
        return ERR_SALT_LEN;
    
    
    blf_ctx *state = get_aligned_state();
    bcrypt_hashpass_asm(state, salt, key, keybytes, hash, rounds);
    free(state);

    return 0;
}

// TODO: return the whole record, not just the hash
char *bcrypt(const char *salt, const char *key, uint16_t keybytes,
             uint64_t rounds)
{
    uint8_t hash[BCRYPT_HASH_BYTES];
    int status;

    if ( (status = bcrypt_asm_wrapper(salt, hash, key, keybytes, rounds)) ) {
        fprintf(stderr, "Error executing bcrypt. Code: 0x%x\n", status);
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