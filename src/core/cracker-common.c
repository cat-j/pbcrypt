#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

    return status;
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