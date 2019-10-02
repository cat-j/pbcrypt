#ifndef _BCRYPT_H_
#define _BCRYPT_H_

#include <stdint.h>

#include "bcrypt-common.h"

/* ========== bcrypt functions ========== */

/* For key schedule.
 * Initialise state to hexadecimal digits of pi.
 */
void blowfish_init_state_asm(blf_ctx *state);

/* For key schedule.
 * Encrypt state boxes and P-array with key and salt.
 */
void blowfish_expand_state_asm(blf_ctx *state, const uint8_t *salt,
                               const char *key, uint16_t keybytes);

/* For key schedule.
 * Encrypt state boxes and P-array with key and 0s.
 */
void blowfish_expand_0_state_asm(blf_ctx *state, const char *key,
                                 uint16_t keybytes);

/* For key schedule.
 * Encrypt state boxes and P-array with salt and 0s.
 * Optimised for working with 128-bit data,
 * i.e. each half is loaded once into a 64-bit register
 * and no further memory accesses are needed for salt data.
 */
void blowfish_expand_0_state_salt_asm(blf_ctx *state, const uint8_t *salt);

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
void bcrypt_hashpass_asm(blf_ctx *state, const uint8_t *salt,
                         const char *key, uint16_t keybytes,
                         uint8_t *hash, uint64_t rounds);

/*
 * Wrapper for bcrypt_hashpass_asm that also initialises state.
 */
int bcrypt_asm_wrapper(const uint8_t *salt, uint8_t *hash, const char *key,
                       uint16_t keybytes, uint64_t rounds);

/*
 *
 */
char *bcrypt(const uint8_t *salt, const char *key, uint16_t keybytes,
             uint8_t log_rounds);


/* ========== Cracker functions ========== */

/*
 * Compare first 21 bytes of two hashes.
 * Designed for cracking.
 */
int hash_match(const uint8_t *hash1, const uint8_t *hash2);

/*
 * Return a 32-bit aligned pointer to an uninitialised
 * Blowfish state.
 */
blf_ctx *get_aligned_state();

#endif