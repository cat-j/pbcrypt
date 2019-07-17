#ifndef _OPENBSD_H_
#define _OPENBSD_H_

#include <stdint.h>
#include "../src/bcrypt.h" // TODO: figure out how to make "bcrypt.h" work

void Blowfish_initstate(blf_ctx *c);

void Blowfish_encipher(const blf_ctx *c, uint32_t *xl, uint32_t *xr);

uint32_t f_wrapper(uint32_t x, const blf_ctx *state);

uint32_t blfrnd_wrapper(const blf_ctx *state, uint32_t xl, uint32_t xr,
                        uint32_t n);

#endif