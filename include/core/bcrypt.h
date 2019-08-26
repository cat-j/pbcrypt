#ifndef _BCRYPT_H_
#define _BCRYPT_H_

#include <stdint.h>

/* ========== Constants/variables/types ========== */

#define BCRYPT_MIN_LOG_ROUNDS    4
#define BCRYPT_MAX_LOG_ROUNDS    32
#define BCRYPT_ENCODED_SALT_SIZE 22
#define BCRYPT_ENCODED_HASH_SIZE 31
#define BCRYPT_RECORD_SIZE       60

#define S_BOX_LENGTH      256
#define P_ARRAY_LENGTH    18
#define BCRYPT_WORDS      6
#define BCRYPT_SALT_BYTES 16
#define BCRYPT_HASH_BYTES 24


/* Blowfish context - taken from OpenBSD source code */
typedef struct BlowfishContext {
    uint32_t S[4][256];    /* S-Boxes */
    uint32_t P[18];        /* Subkeys */
} blf_ctx;

/* Blowfish context with 4 copies of each element */
typedef struct ParallelBlowfishContext {
    uint32_t S[4][1024];
    uint32_t P[72];
} p_blf_ctx;

extern int variant; // unrolled loops, P-array in YMM registers, etc


/* ========== bcrypt functions ========== */

/* For key schedule.
 * Initialise state to hexadecimal digits of pi.
 */
void blowfish_init_state_asm(blf_ctx *state);

/* For key schedule.
 * Encrypt state boxes and P-array with key and salt.
 */
void blowfish_expand_state_asm(blf_ctx *state, const char *salt,
                               const char *key, uint16_t keybytes);

/* For key schedule.
 * Encrypt state boxes and P-array with key and 0s.
 */
void blowfish_expand_0_state_asm(blf_ctx *state, const char *key,
                                 uint64_t keybytes);

/* For key schedule.
 * Encrypt state boxes and P-array with salt and 0s.
 * Optimised for working with 128-bit data,
 * i.e. each half is loaded once into a 64-bit register
 * and no further memory accesses are needed for salt data.
 */
void blowfish_expand_0_state_salt_asm(blf_ctx *state, const char *salt);

/*
 * Encrypt data with P-array values.
 * This is not actually used inside other ASM bcrypt/blowfish functions;
 * instead, they call an optimised function in which data is already
 * stored in a register. It's not exported, as it doesn't follow cdecl.
 */
void blowfish_encipher_asm(const blf_ctx *state, uint64_t *data);

/*
 * Encrypt data by enciphering each of its 64-bit blocks.
 * Calls an optimised, non-exported, non-C-compliant variant
 * of blowfish_encipher_asm.
 */
void blowfish_encrypt_asm(const blf_ctx *state, uint64_t *data);

/*
 * Hash password (key) and store result in hash.
 * Variable rounds corresponds to actual number of rounds,
 * not log.
 */
void bcrypt_hashpass_asm(blf_ctx *state, const char *salt,
                         const char *key, uint16_t keybytes,
                         uint8_t *hash, uint64_t rounds);

/*
 * Wrapper for bcrypt_hashpass_asm that also initialises state.
 */
int bcrypt_asm_wrapper(const char *salt, uint8_t *hash, const char *key,
                       uint16_t keybytes, uint64_t rounds);

/*
 *
 */
char *bcrypt(const char *salt, const char *key, uint16_t keybytes,
             uint64_t rounds);


/* ========== Parallelised functions ========== */

void blowfish_parallelise_state(p_blf_ctx *state, blf_ctx *src);


/* ========== Cracker functions ========== */

/*
 * Parse a bcrypt password record as it would be stored
 * in a shadow password file, e.g.
 * "$2b$08$Z1/fWkjsYUDNSCDAQS3HOO.jYkAT2lI6RZco8UP86hp5oqS7.kZJV".
 */
int get_record_data(char *record, uint8_t *ciphertext,
                    uint8_t *salt, uint64_t *rounds);

int hash_match(const uint8_t *hash1, const uint8_t *hash2);

blf_ctx *get_aligned_state();


/* ========== Macro wrappers for testing ========== */

uint32_t f_asm(uint32_t x, const blf_ctx *state);

uint32_t blowfish_round_asm(uint32_t xl, uint32_t xr, const blf_ctx *state,
                            uint32_t n);

uint64_t reverse_bytes(uint64_t data);

void copy_ctext_asm(uint64_t *data, const char *ctext);

void load_salt_and_p(blf_ctx *state, uint8_t *salt);

#endif