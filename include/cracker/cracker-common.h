#ifndef _CRACKER_COMMON_H_
#define _CRACKER_COMMON_H_

#include <stdint.h>
#include <stdlib.h>

#include "bcrypt-common.h"


/* ========== Macros ========== */

#define DEFAULT_N_PASSWORDS 1024

/* Macros for experiment measurements */

#define PRINT_HEADER \
fprintf(r_stream, "Passwords;Length;Passwords per batch;" \
    "Rounds log;Variant;Time hashing;Total time\n")

#define PRINT_MEASUREMENTS \
fprintf(r_stream, "%lu;%lu;%lu;%u;%d;%f;%f\n", \
    passwords_cracked, pass_length, n_passwords, \
    rounds_log, variant, seconds, total_seconds)
    

/* ========== Variables ========== */

/* Configuration */
int measure;
char *results_filename;

/* Initial arguments */
char record[BCRYPT_RECORD_SIZE+1];
char filename[256];
size_t n_passwords;
char *end;

/* Record data */
uint8_t record_ciphertext[BCRYPT_HASH_BYTES-3];
char salt[BCRYPT_SALT_BYTES+1];
uint8_t rounds_log;
uint64_t rounds;

/* Cracking */
size_t pass_length, batch_size, bytes_read;
char *current_batch;
char flush_newline; // skip first newline for cleaner loops

/* Measurement */
FILE *r_stream;
uint64_t passwords_cracked;
uint64_t total_time_hashing;
uint64_t start_time, end_time;
uint64_t total_start_time, total_end_time;


/* ========== Functions ========== */

/* Process command line arguments.
 * If successful, overwrites record and n_passwords
 * (the latter falls back to DEFAULT_N_PASSWORDS
 * if no third argument is provided.)
 * Return 0 on success and ERR_ARGS on error.
 */
int process_args(int argc, char const *argv[]);

/*
 * Process password length from wordlist file
 * and write a file pointer to it in `*wl_stream`.
 * Return 0 on success and corresponding error code otherwise.
 */
int process_wordlist(FILE **wl_stream);

/*
 * If `measure` is enabled, open results file,
 * write header if necessary and initialise variables.
 * `start_time` is not initialised, as function context switch
 * would add a small overhead and affect measurements.
 * Return 0 on success and corresponding error code otherwise.
 */
int initialise_measure();

/*
 * Parse a bcrypt password record as it would be stored
 * in a shadow password file, e.g.
 * "$2b$08$Z1/fWkjsYUDNSCDAQS3HOO.jYkAT2lI6RZco8UP86hp5oqS7.kZJV".
 * Whilst parsing record, print information to standard output.
 * Return 0 on success and corresponding error code otherwise.
 */
int get_record_data(char *record, uint8_t *ciphertext,
                    uint8_t *salt, uint64_t *rounds);

#endif