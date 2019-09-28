#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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