#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base64.h"
#include "bcrypt-errors.h"
#include "cracker-common.h"
#include "print.h"

int process_args(int argc, char const *argv[]) {
    switch(argc) {
        case(3):
            n_passwords = DEFAULT_N_PASSWORDS;
            break;
        case(4):
            n_passwords = strtoul(argv[3], &end, 10);
            // Make sure it's divisible by 4
            if ((n_passwords >> 2) << 2 != n_passwords || n_passwords == 0)
                return ERR_N_PASSWORDS;
            break;
        default:
            fprintf(stderr,
                "Usage: cracker <RECORD> <PATH_TO_WORDLIST> <N_PASSWORDS>\n");
            return ERR_ARGS;
            break;
    }

    strncpy(record, argv[1], BCRYPT_RECORD_SIZE);
    record[BCRYPT_RECORD_SIZE] = 0;

    strncpy(filename, argv[2], strlen(argv[2]));
    filename[strlen(argv[2])] = 0;

    return 0;
}

// TODO: return 0 on success

int process_wordlist(FILE **wl_stream) {
    *wl_stream = fopen(filename, "r");

    if (!(*wl_stream)) {
        fprintf(stderr, BOLD_RED("Error: unable to open file %s.\n"), filename);
        return ERR_OPEN_FILE;
    }

    int status = fscanf(*wl_stream, "%lu", &pass_length);
    if (status < 1) {
        fprintf(stderr, BOLD_RED("Error: unable to process password length.\n"));
        return ERR_FILE_DATA;
    }
    fread(&flush_newline, 1, 1, *wl_stream);

    printf(BOLD_YELLOW("Password length: ") "%ld\n", pass_length);

    return 0;
}

int initialise_measure() {
    // Initialise file for measurements if needed
    int write_header = 0;

    if (access(results_filename, F_OK) == -1) {
        // File doesn't exist, header must be written
        write_header = 1;
    }

    r_stream = fopen(results_filename, "a");
    
    if (!r_stream) {
        printf(BOLD_RED("Could not open file %s.\n"), (char *) &results_filename);
        return ERR_OPEN_FILE;
    }

    if (write_header) {
        fprintf(r_stream, "Passwords;Length;Passwords per batch;"
            "Variant;Time hashing;Total time\n");
    }

    passwords_cracked = 0;
    total_time_hashing = 0;

    return 0;
}

int get_record_data(char *record, uint8_t *ciphertext,
                    uint8_t *salt, uint64_t *rounds)
{
    printf(BOLD_MAGENTA("Processing record...\n"));
    printf(BOLD_YELLOW("Record: ") "%s\n", record);
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
    printf(BOLD_YELLOW("Rounds log: ") "%d\n", log_rounds);
    record += 3;
    
    *rounds = 1U << log_rounds;

    // Decode salt
    if (decode_base64(salt, BCRYPT_SALT_BYTES, record))
        return ERR_BASE64;
    salt[BCRYPT_SALT_BYTES] = 0; // for pretty printing
    printf(BOLD_YELLOW("Salt: ") "%s\n", salt);
    record += BCRYPT_ENCODED_SALT_SIZE;

    // Decode ciphertext
    if (decode_base64(ciphertext, 21, record))
        return ERR_BASE64;
    printf(BOLD_YELLOW("Hash to crack: "));
    print_hex(ciphertext, BCRYPT_HASH_BYTES-3);

    return 0;
}

int is_valid_version(char c) {
    return c == 'a' || c == 'b' || c == 'x' || c == 'y';
}