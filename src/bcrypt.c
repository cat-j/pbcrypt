#include <ctype.h>
#include <malloc.h>
#include <string.h>

#include "base64.h"
#include "bcrypt.h"

#define BCRYPT_MIN_LOG_ROUNDS    4
#define BCRYPT_MAX_LOG_ROUNDS    32
#define BCRYPT_ENCODED_SALT_SIZE 22
#define BCRYPT_ENCODED_HASH_SIZE 31
#define BCRYPT_RECORD_SIZE       60

#define ERR_RECORD_LEN    0x10010
#define ERR_RECORD_FORMAT 0x10020
#define ERR_VERSION       0x10030
#define ERR_ROUNDS        0x10040
#define ERR_BASE64        0x10050

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