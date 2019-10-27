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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base64.h"
#include "cracker-common.h"
#include "cracker-errors.h"
#include "print.h"

int process_args(int argc, char const *argv[]) {
    switch(argc) {
        case(3):
            n_passwords = DEFAULT_N_PASSWORDS;
            break;
        case(4):
            n_passwords = strtoul(argv[3], &end, 10);
            
            // pbcrypt with four passwords
            if (variant == 3 || variant == 8 || variant == 10) {
            // Make sure it's divisible by 4
                if ((n_passwords >> 2) << 2 != n_passwords || n_passwords == 0)
                    return ERR_N_PASSWORDS;
            }

            // double pbcrypt, it must also be divisible by 8
            if (variant == 11) {
                if ((n_passwords >> 3) << 3 != n_passwords || n_passwords == 0)
                return ERR_N_PASSWORDS;
            }
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
        printf(BOLD_RED("Could not open file %s.\n"), results_filename);
        return ERR_OPEN_FILE;
    }

    if (write_header) {
        PRINT_HEADER;
    }

    passwords_cracked = 0;
    total_time_hashing = 0;

    return 0;
}

int get_record_data(char *record, uint8_t *ciphertext,
                    uint8_t *salt, uint64_t *rounds)
{
    printf(BOLD_MAGENTA("\nProcessing record...\n"));
    printf(BOLD_YELLOW("Record: ") "%s\n", record);

    if (strlen(record) != BCRYPT_RECORD_SIZE)
        return ERR_RECORD_LEN;

    if (record[0] != '$' || record[3] != '$')
        return ERR_RECORD_FORMAT;
    record++;

    if (record[0] != '2' || record[1] != 'a' || record[1] != 'b')
        return ERR_VERSION;
    record += 3;

    if (!isdigit((unsigned char)record[0]) ||
        !isdigit((unsigned char)record[1]) || record[2] != '$')
        return ERR_ROUNDS;

    // Parse rounds
    rounds_log = (record[1] - '0') + ((record[0] - '0') * 10);
    if (rounds_log < BCRYPT_MIN_ROUNDS_LOG || rounds_log > BCRYPT_MAX_ROUNDS_LOG)
        return ERR_ROUNDS;
    printf(BOLD_YELLOW("Rounds log: ") "%d\n", rounds_log);
    record += 3;
    
    *rounds = 1U << rounds_log;

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
