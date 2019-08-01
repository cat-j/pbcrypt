#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bcrypt.h"
#include "bcrypt_constants.h"

#define DEFAULT_N_PASSWORDS 1024

#define ERR_ARGS 0x20010

int main(int argc, char const *argv[]) {
    // Process arguments
    char record[BCRYPT_RECORD_SIZE+1];
    char filename[256];
    size_t n_passwords;
    char *end;

    strncpy(record, argv[1], BCRYPT_RECORD_SIZE);
    strncpy(filename, argv[2], strlen(argv[2]));

    switch(argc) {
        case(3):
            n_passwords = DEFAULT_N_PASSWORDS;
            break;
        case(4):
            n_passwords = strtoul(argv[3], &end, 10);
            break;
        default:
            fprintf(stderr, "Usage: cracker <RECORD> <PATH_TO_WORDLIST> <N_PASSWORDS>\n");
            return ERR_ARGS;
            break;
    }

    
    // Process record parameters
    char record_ciphertext[BCRYPT_HASH_BYTES-3];
    char salt[BCRYPT_SALT_BYTES];
    uint64_t rounds;

    int status = get_record_data(&record, &record_ciphertext, &salt, &rounds);
    if (status) {
        // Error processing record
        fprintf(stderr, "Error: get_record_data returned status %x.\n",
                status);
        return status;
    }


    // Read wordlist file
    FILE *wl_stream;
    
    
    return 0;
}
