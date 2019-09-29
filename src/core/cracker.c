#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bcrypt.h"
#include "bcrypt-constants.h"
#include "config.h"
#include "cracker-common.h"
#include "print.h"

// Usage examples:
// ./build/cracker \$2b\$08\$Z1/fWkjsYUDNSCDAQS3HOO.jYkAT2lI6RZco8UP86hp5oqS7.kZJV ./wordlists/test_wordlist
// ./build/cracker \$2b\$08\$Z1/fWkjsYUDNSCDAQS3HOO40KV54lhKyb96cCVfrBZ0rw6Z.525GW ./wordlists/wordlist

// TODO: accept different bcrypt versions
int bcrypt_asm_wrapper(const char *salt, uint8_t *hash, const char *key,
                       uint16_t keybytes, uint64_t rounds)
{
    if (!salt)
        return ERR_BAD_SALT;
    
    if (!key)
        return ERR_BAD_KEY;

    if (!hash)
        return ERR_BAD_HASH;

    if (strlen(salt) != BCRYPT_SALT_BYTES)
        return ERR_SALT_LEN;
    
    
    blf_ctx *state = get_aligned_state();
    bcrypt_hashpass_asm(state, salt, key, keybytes, hash, rounds);
    free(state);

    return 0;
}

/*
 * Main password cracker function.
 * Wordlist passwords must be the same length (in bytes)
 * and newline-separated, and the first line of the file
 * should be the password length.
 * If `measure` is set, it will also store some measurements
 * to a .csv file, which is useful for experiments.
 */
int main(int argc, char const *argv[]) {
    load_config();

    /////// Process arguments ///////

    int status = process_args(argc, argv);
    if (status) {
        fprintf(stderr, BOLD_RED("Error: process_args returned status 0x%x.\n"),
                status);
        return status;
    }

    /////// Process record parameters ///////
    
    uint8_t record_ciphertext[BCRYPT_HASH_BYTES-3];
    char salt[BCRYPT_SALT_BYTES+1];
    uint64_t rounds;

    status = get_record_data((char *) &record, (uint8_t *) &record_ciphertext,
        (uint8_t *) &salt, &rounds);
    if (status) {
        // Error processing record
        fprintf(stderr, BOLD_RED("Error: get_record_data returned status 0x%x.\n"),
                status);
        return status;
    }

    // Read info from wordlist file
    FILE *wl_stream;
    status = process_wordlist(&wl_stream);

    if (status < 1) {
        // Error processing wordlist
        fprintf(stderr, BOLD_RED("Error: process_wordlist returned status 0x%x.\n"),
                status);
        return status;
    }

    batch_size = n_passwords * (pass_length+1); // add 1 for \n, later \0
    current_batch = malloc(batch_size);

    
    /////// Crack password ///////

    uint8_t hash[BCRYPT_HASH_BYTES];
    blf_ctx *state = get_aligned_state();
    char *current_pass, *matching_pass;
    int found = 0;

    if (measure) {
        status = initialise_measure();
        
        if (status) {
            fprintf(stderr, BOLD_RED("Error: initialise_measure returned status 0x%x.\n"),
                status);
            return status;
        }

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

    printf(BOLD_MAGENTA("\nFinished cracking.\n"));

    if (!found) {
        printf("No matches found in %s.\n", filename);
    } else {
        printf("Found plaintext password " BOLD_MAGENTA("%s") " with matching hash.\n",
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
