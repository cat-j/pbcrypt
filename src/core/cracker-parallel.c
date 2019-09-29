#include <stdio.h>
#include <time.h>

#include "bcrypt.h"
#include "bcrypt-constants.h"
#include "bcrypt-parallel.h"
#include "config.h"
#include "cracker-common.h"
#include "print.h"

// Usage examples:
// ./build/cracker-parallel \$2b\$08\$Z1/fWkjsYUDNSCDAQS3HOO.jYkAT2lI6RZco8UP86hp5oqS7.kZJV ./wordlists/test_wordlist
// ./build/cracker-parallel \$2b\$08\$Z1/fWkjsYUDNSCDAQS3HOO40KV54lhKyb96cCVfrBZ0rw6Z.525GW ./wordlists/wordlist

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


    size_t scale = 4; // TODO: move DWORDS_PER_XMM to another file
    size_t password_groups = n_passwords / scale;
    size_t group_length = pass_length*scale;
    batch_size = n_passwords * (pass_length+1); // add 1 for \n, later \0
    current_batch = malloc(batch_size);


    /////// Crack password ///////

    uint8_t hashes[BCRYPT_HASH_BYTES*scale];
    p_blf_ctx *p_state = get_aligned_p_state();
    p_blf_ctx *initial_p_state = get_aligned_p_state();
    char *current_passwords, *matching_pass;
    int found = 0;
    int matching_pass_idx = -1;

    if (measure) {
        status = initialise_measure();
        
        if (status) {
            fprintf(stderr, BOLD_RED("Error: initialise_measure returned status 0x%x.\n"),
                status);
            return status;
        }

        total_start_time = clock();
    }

    // Initialise parallel state
    blowfish_parallelise_state(initial_p_state, &initstate_asm);
    // printf(BOLD_YELLOW("Current batch:\n"));
    // printf("%s \n", current_batch);
    
    while (!found &&
           (bytes_read = fread(current_batch, 1, batch_size, wl_stream) > 0))
    {
        // printf(BOLD_YELLOW("Current batch:\n"));
        // printf("%s", current_batch);
        // Null-terminate each password
        for (size_t i = pass_length; i < batch_size; i += pass_length+1) {
            current_batch[i] = 0;
        }

        // Hash passwords currently in the buffer to see if any of them matches
        for (size_t j = 0; j < password_groups; ++j) {
            current_passwords = &current_batch[j*group_length];

            if (measure) {
                start_time = clock();
            }
        
            blowfish_init_state_parallel(p_state, initial_p_state);
            bcrypt_hashpass_parallel(p_state, salt, current_passwords,
                pass_length, hashes, rounds);
        
            if (measure) {
                end_time = clock();
                total_time_hashing += end_time - start_time;
                ++passwords_cracked;
            }

            matching_pass_idx = hash_match_parallel(hashes, record_ciphertext);

            if (matching_pass_idx >= 0) {
                // Cracked the password!
                found = 1;
                matching_pass = malloc(pass_length+1);
                strncpy(matching_pass, current_passwords[matching_pass_idx * (pass_length+1)],
                    pass_length);
                break;
            }
        }
    }

    printf(BOLD_MAGENTA("\nFinished cracking.\n"));

    if (!found) {
        printf("No matches found in %s.\n", filename);
    } else {
        printf("Found plaintext password " BOLD_MAGENTA("%s") " with matching hash.\n",
               matching_pass);
        free(matching_pass);
    }


    /////// Finish ///////

    free(p_state);
    free(current_batch);
    fclose(wl_stream);

    return 0;
}