#include <stdio.h>
#include <stdlib.h>

#include "bcrypt.h"

#define DEFAULT_N_PASSWORDS 1024

int main(int argc, char const *argv[]) {
    // Process arguments
    char record[BCRYPT_RECORD_SIZE+1];
    char filename[256];
    size_t n_passwords;
    char *end;

    switch(argc) {
        case(2):
            n_passwords = DEFAULT_N_PASSWORDS;
            break;
        case(3):
            n_passwords = strtoul(argv[2], &end, 10);
            break;
        default:
            return EXIT_FAILURE;
            break;
    }


    // Read wordlist file
    FILE *wl_stream;
    
    
    return 0;
}
