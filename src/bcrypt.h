#ifndef _BCRYPT_H_
#define _BCRYPT_H_

#include <stdint.h>

#define S_BOX_LENGTH   256
#define P_ARRAY_LENGTH 18
#define BCRYPT_WORDS   6

/* Blowfish context - taken from OpenBSD source code */
typedef struct BlowfishContext {
    uint32_t S[4][256];    /* S-Boxes */
    uint32_t P[18];    /* Subkeys */
} blf_ctx;


/* bcrypt functions */

void blowfish_init_state_asm(blf_ctx *state);

void blowfish_expand_state_asm(blf_ctx *state, const char *salt,
                               uint16_t saltbytes, // TODO: remove this parameter
                               const char *key, uint16_t keybytes);

void blowfish_expand_0_state_asm(blf_ctx *state, const char *key,
                                 uint64_t keybytes);

void blowfish_expand_0_state_salt_asm(blf_ctx *state, const char *salt);

void blowfish_encipher_asm(const blf_ctx *state, uint64_t *data);

void blowfish_encrypt_asm(const blf_ctx *state, uint64_t *data);

void bcrypt_hashpass_asm(blf_ctx *state, const char *salt,
                         uint8_t *hash, const char *key,
                         uint16_t keybytes, uint64_t rounds);


/* Testing functions */

uint32_t f_asm(uint32_t x, const blf_ctx *state);

uint32_t blowfish_round_asm(uint32_t xl, uint32_t xr, const blf_ctx *state,
                            uint32_t n);

uint64_t reverse_bytes(uint64_t data);

void copy_ctext_asm(uint64_t *data, const char *ctext);


/* Utilities */

void b64_encode(char *dst, char *src, uint64_t srcbytes);

void b64_decode(char *dst, char *src, uint64_t srcbytes);

#endif