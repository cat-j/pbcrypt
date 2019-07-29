#include <ctype.h>
#include <malloc.h>
#include <string.h>

#include "base64.h"
#include "bcrypt.h"

#define BCRYPT_MIN_LOG_ROUNDS 4
#define BCRYPT_MAX_LOG_ROUNDS 32
#define BCRYPT_ENCODED_SALT_SIZE 22
#define BCRYPT_ENCODED_HASH_SIZE 31
#define BCRYPT_RECORD_SIZE 60

// TODO: design error format
#define ERR_RECORD_FORMAT 1
#define ERR_VERSION 2
#define ERR_ROUNDS 3
#define ERR_BASE64 4

int get_record_data(char *record, uint8_t *ciphertext,
                    uint8_t *salt, uint64_t *rounds)
{
    uint8_t log_rounds;

    if (strlen(record) != BCRYPT_RECORD_SIZE)
        return ERR_RECORD_FORMAT;

    if (record[0] != '$' || record[3] != '$')
        return ERR_RECORD_FORMAT;
    record++;

    // This cracker is only for version $2b$ password records
    if (record[0] != '2' || record[1] != 'b')
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
    if (decode_base64(ciphertext, BCRYPT_WORDS << 2, record))
        return ERR_BASE64;

    return 0;
}