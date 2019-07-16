#include <stdint.h>

#ifndef _BCRYPT_H_
#define _BCRYPT_H_

#define S_BOX_LENGTH 256
#define P_ARRAY_LENGTH 18

/* Blowfish context - taken from OpenBSD source code */
typedef struct BlowfishContext {
	uint32_t S[4][256];	/* S-Boxes */
	uint32_t P[18];	/* Subkeys */
} blf_ctx;

void blowfish_init_state_asm(blf_ctx *state);

void blowfish_expand_state_asm(blf_ctx *state, const char *salt,
							   const char *key, uint16_t keybytes);
							   
uint32_t f_asm(uint32_t x, const blf_ctx *state);

#endif