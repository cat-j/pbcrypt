#ifndef _CRACKER_COMMON_H_
#define _CRACKER_COMMON_H_

#include <stdint.h>
#include <stdlib.h>

#include "bcrypt-common.h"

#define DEFAULT_N_PASSWORDS 1024

#define ERR_ARGS      0x20010
#define ERR_OPEN_FILE 0x20020
#define ERR_FILE_DATA 0x20030


/* Configuration variables */
int measure;
char results_filename[256];

/* Initial arguments */
char record[BCRYPT_RECORD_SIZE+1];
char filename[256];
size_t n_passwords;
char *end;

/* Record data */
uint8_t record_ciphertext[BCRYPT_HASH_BYTES-3];
char salt[BCRYPT_SALT_BYTES+1];
uint64_t rounds;

/* Cracking variables */
size_t pass_length, batch_size, bytes_read;
char *current_batch;
char flush_newline; // skip first newline for cleaner loops


/* Functions */

/* Process command line arguments.
 * If successful, overwrites record and n_passwords
 * (the latter falls back to DEFAULT_N_PASSWORDS
 * if no third argument is provided.)
 * Returns 0 on success and ERR_ARGS on error.
 */
int process_args(int argc, char const *argv[]);

void print_record_info();

#endif