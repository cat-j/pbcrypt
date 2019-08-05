#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bcrypt.h"
#include "bcrypt_constants.h"
#include "print.h"

#define DEFAULT_N_PASSWORDS 1024

#define MEASURE_TIME 1 // TODO: make this an environment variable

#define ERR_ARGS      0x20010
#define ERR_OPEN_FILE 0x20020
#define ERR_FILE_DATA 0x20030

/*
 * Main password cracker function.
 * Wordlist passwords must be the same length and newline-separated,
 * and the first line of the file should be the password length.
 */
int main(int argc, char const *argv[]) {
    // Process arguments
    char record[BCRYPT_RECORD_SIZE+1];
    char filename[256];
    size_t n_passwords;
    char *end;

    switch(argc) {
        case(3):
            n_passwords = DEFAULT_N_PASSWORDS;
            break;
        case(4):
            n_passwords = strtoul(argv[3], &end, 10);
            break;
        default:
            fprintf(stderr,
                "Usage: cracker <RECORD> <PATH_TO_WORDLIST> <N_PASSWORDS>\n");
            return ERR_ARGS;
            break;
    }

    strncpy(record, argv[1], BCRYPT_RECORD_SIZE);
    strncpy(filename, argv[2], strlen(argv[2]));

    
    // Process record parameters
    uint8_t record_ciphertext[BCRYPT_HASH_BYTES-3];
    char salt[BCRYPT_SALT_BYTES+1];
    uint64_t rounds;

    int status = get_record_data((char *) &record, (uint8_t *) &record_ciphertext,
        (uint8_t *) &salt, &rounds);
    if (status) {
        // Error processing record
        fprintf(stderr, "Error: get_record_data returned status %x.\n",
                status);
        return status;
    }

    salt[BCRYPT_SALT_BYTES] = 0; // for pretty printing
    printf("Salt: %s\n", (char *) &salt);
    printf("Rounds: %ld\n", rounds);
    printf("Hash to crack: ");
    print_hex((uint8_t *) &record_ciphertext, BCRYPT_HASH_BYTES-3);


    // Read info from wordlist file
    size_t pass_length, batch_size, bytes_read;
    char *current_batch;
    char flush_newline;
    FILE *wl_stream = fopen(filename, "rb");

    if (!wl_stream) {
        fprintf(stderr, "Error: unable to open file %s.\n", filename);
        return ERR_OPEN_FILE;
    }

    status = fscanf(wl_stream, "%lu", &pass_length);
    fread(&flush_newline, 1, 1, wl_stream);

    if (status < 1) {
        fprintf(stderr, "Error: unable to process password length.\n");
        return ERR_FILE_DATA;
    }

    printf("Password length: %ld\n", pass_length);

    batch_size = n_passwords * (pass_length+1); // add 1 for \n, later \0
    current_batch = malloc(batch_size);

    
    // Crack password
    uint8_t *hash = malloc(BCRYPT_HASH_BYTES+1);
    blf_ctx *state = get_aligned_state();
    char *current_pass, *matching_pass;
    int found = 0;
    
    #ifdef MEASURE_TIME
        uint64_t total_time = 0;
        uint64_t start_time, end_time;
    #endif

    // Read several passwords into buffer and hash them
    while (!found &&
           (bytes_read = fread(current_batch, 1, batch_size, wl_stream) > 0))
    {
        // Null-terminate each password
        for (size_t i = pass_length; i < batch_size; i += pass_length+1) {
            current_batch[i] = 0;
        }

        // Hash passwords currently in the buffer to see if any of them matches
        for (size_t j = 0; j < n_passwords; ++j) {
            current_pass = &current_batch[j*(pass_length+1)];

            #ifdef MEASURE_TIME
                start_time = clock();
            #endif

            blowfish_init_state_asm(state);
            bcrypt_hashpass_asm(state, salt, current_pass, pass_length, hash, rounds);
            
            #ifdef MEASURE_TIME
                end_time = clock();
                total_time += end_time - start_time;
            #endif

            if (hash_match(hash, record_ciphertext)) {
                // Cracked the password!
                found = 1;
                matching_pass = malloc(pass_length+1);
                strncpy(matching_pass, current_pass, pass_length);
                break;
            }
        }
    }

    if (!found) {
        printf("No matches found in %s.\n", filename);
    } else {
        printf("Found plaintext password \033[1;35m%s\033[0m with matching hash.\n",
               matching_pass);
        free(matching_pass);
    }

    #ifdef MEASURE_TIME
        double seconds = (double) total_time / CLOCKS_PER_SEC;
        printf("Time elapsed: %f seconds.\n", seconds);
    #endif


    // Finish
    free(hash);
    free(state);
    fclose(wl_stream);
    free(current_batch);
    
    
    return 0;
}
