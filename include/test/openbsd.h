#ifndef _OPENBSD_H_
#define _OPENBSD_H_

#include <stdint.h>
#include "bcrypt.h"

#define BCRYPT_MAXSALT 16     /* Precomputation is just so nice */

/*
 * Code from OpenBSD implementation of bcrypt,
 * isolated for easy testing.
 */

void Blowfish_initstate(blf_ctx *c);

void Blowfish_initstate_dummy(blf_ctx *c);

void Blowfish_expandstate(blf_ctx *c, const uint8_t *data, uint16_t databytes,
    const uint8_t *key, uint16_t keybytes);

void Blowfish_expand0state(blf_ctx *c, const uint8_t *key, uint16_t keybytes);

void Blowfish_expand0statesalt(blf_ctx *c, const uint8_t *key, uint16_t keybytes);

void Blowfish_encipher(const blf_ctx *c, uint32_t *xl, uint32_t *xr);
void Blowfish_encipher_debug(const blf_ctx *c, uint32_t *xl, uint32_t *xr);

void blf_enc(const blf_ctx *c, uint32_t *data, uint16_t blocks);

uint32_t Blowfish_stream2word(const uint8_t *data, uint16_t databytes,
    uint16_t *current);

uint32_t f_wrapper(uint32_t x, const blf_ctx *state);

uint32_t blfrnd_wrapper(const blf_ctx *state, uint32_t xl, uint32_t xr,
                        uint32_t n);

void copy_ctext_openbsd(uint32_t *cdata, const char *ctext, size_t scale);

int bcrypt_hashpass(blf_ctx *state, const char *key, const char *salt,
                    uint64_t rounds, uint8_t *hash);

#endif