#ifndef _OPENBSD_H_
#define _OPENBSD_H_

#include <stdint.h>
#include "../src/bcrypt.h" // TODO: figure out how to make "bcrypt.h" work

void Blowfish_initstate(blf_ctx *c);

uint32_t f_wrapper(uint32_t x, const blf_ctx *state);

#endif