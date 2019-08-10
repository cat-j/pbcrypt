#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bcrypt.h"
#include "bcrypt-constants.h"
#include "config.h"
#include "print.h"


#define DEFAULT_N_PASSWORDS 1024

#define ERR_ARGS      0x20010
#define ERR_OPEN_FILE 0x20020
#define ERR_FILE_DATA 0x20030

// Usage examples:
// ./build/cracker \$2b\$08\$Z1/fWkjsYUDNSCDAQS3HOO.jYkAT2lI6RZco8UP86hp5oqS7.kZJV ./wordlists/test_wordlist
// ./build/cracker \$2b\$08\$Z1/fWkjsYUDNSCDAQS3HOO40KV54lhKyb96cCVfrBZ0rw6Z.525GW ./wordlists/wordlist


/* Configuration variables */

int measure;
char results_filename[256];


/*
 * Main password cracker function.
 * Wordlist passwords must be the same length (in bytes)
 * and newline-separated, and the first line of the file
 * should be the password length.
 * If MEASURE_TIME is set, it will also store some measurements
 * to a .csv file, which is useful for experiments.
 */
int main(int argc, char const *argv[]) {
    load_config();

    /////// Process arguments ///////
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
    record[BCRYPT_RECORD_SIZE] = 0;

    strncpy(filename, argv[2], strlen(argv[2]));
    filename[strlen(argv[2])] = 0;

    
    /////// Process record parameters ///////
    
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
    char flush_newline; // skip first newline for cleaner loops
    FILE *wl_stream = fopen(filename, "r");

    if (!wl_stream) {
        fprintf(stderr, "Error: unable to open file %s.\n", filename);
        return ERR_OPEN_FILE;
    }

    status = fscanf(wl_stream, "%lu", &pass_length);
    if (status < 1) {
        fprintf(stderr, "Error: unable to process password length.\n");
        return ERR_FILE_DATA;
    }
    fread(&flush_newline, 1, 1, wl_stream);


    printf("Password length: %ld\n", pass_length);

    batch_size = n_passwords * (pass_length+1); // add 1 for \n, later \0
    current_batch = malloc(batch_size);

    
    /////// Crack password ///////

    uint8_t hash[BCRYPT_HASH_BYTES+1];
    blf_ctx *state = get_aligned_state();
    char *current_pass, *matching_pass;
    int found = 0;
    
    // Declare variables for measuring
    FILE *r_stream;
    uint64_t passwords_cracked;
    uint64_t total_time_hashing;
    uint64_t start_time, end_time;
    uint64_t total_start_time, total_end_time;
    total_start_time = clock();

    if (measure) {
        // Initialise file for measurements if needed
        int write_header = 0;

        if (access(results_filename, F_OK) == -1) {
            // File doesn't exist, header must be written
            write_header = 1;
        }

        r_stream = fopen(results_filename, "a");
        
        if (!r_stream) {
            printf("Could not open file %s.\n", (char *) &results_filename);
            return ERR_OPEN_FILE;
        }

        if (write_header) {
            fprintf(r_stream, "Passwords;Length;Passwords per batch;"
                "Variant;Time hashing;Total time\n");
        }

        passwords_cracked = 0;
        total_time_hashing = 0;
        total_start_time = clock();
    }
        


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

            if (measure) {
                start_time = clock();
            }
        
            blowfish_init_state_asm(state);
            bcrypt_hashpass_asm(state, salt, current_pass, pass_length,
                (uint8_t *) &hash, rounds);
        
            if (measure) {
                end_time = clock();
                total_time_hashing += end_time - start_time;
                ++passwords_cracked;
            }
        
            if (hash_match(hash, record_ciphertext)) {
                // Cracked the password!
                found = 1;
                matching_pass = malloc(pass_length+1);
                strncpy(matching_pass, current_pass, pass_length);
                break;
            }
        }
    }

    if (measure) {
        total_end_time = clock();
    }

    if (!found) {
        printf("No matches found in %s.\n", filename);
    } else {
        printf("Found plaintext password \033[1;35m%s\033[0m with matching hash.\n",
               matching_pass);
        free(matching_pass);
    }

    if (measure) {
        double seconds = (double) total_time_hashing / CLOCKS_PER_SEC;
        printf("Time spent hashing: %f seconds.\n", seconds);

        double total_seconds =
            (double) (total_end_time - total_start_time) / CLOCKS_PER_SEC;
        printf("Total time elapsed: %f seconds.\n", total_seconds);

        printf("Number of passwords cracked: %lu.\n", passwords_cracked);

        fprintf(r_stream, "%lu;%lu;%lu;%d;%f;%f\n",
            passwords_cracked, pass_length, n_passwords, variant,
            seconds, total_seconds);

        fclose(r_stream);
    }


    /////// Finish ///////

    free(state);
    free(current_batch);
    fclose(wl_stream);
    
    
    return 0;
}
