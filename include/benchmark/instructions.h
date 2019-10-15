#ifndef _INSTRUCTIONS_H_
#define _INSTRUCTIONS_H_

#include <stdint.h>

void benchmark_read(uint64_t iterations, uint64_t *data);
void benchmark_write(uint64_t iterations, uint64_t *data);
void benchmark_vpextrd(uint64_t iterations);
void benchmark_pextrq(uint64_t iterations);
void benchmark_pinsrq(uint64_t iterations);
void benchmark_vpermq(uint64_t iterations);
void benchmark_vpshufb(uint64_t iterations);

#endif