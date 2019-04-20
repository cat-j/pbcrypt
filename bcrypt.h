#include <stdint.h>

#ifndef _BCRYPT_H_
#define _BCRYPT_H_

/* Blowfish context - taken from OpenBSD source code */
typedef struct BlowfishContext {
	uint32_t S[4][256];	/* S-Boxes */
	uint32_t P[18];	/* Subkeys */
} blf_ctx;

void blowfish_expand_state_asm(blf_ctx* state);

#endif