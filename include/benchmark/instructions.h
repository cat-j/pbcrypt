/*
 * pbcrypt: parallel bcrypt for password cracking
 * Copyright (C) 2019  Catalina Juarros <https://github.com/cat-j>
 *
 * This file is part of pbcrypt.
 * 
 * pbcrypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * 
 * pbcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with pbcrypt.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef _INSTRUCTIONS_H_
#define _INSTRUCTIONS_H_

#include <stdint.h>

void benchmark_read(uint64_t iterations, uint64_t *data);
void benchmark_write(uint64_t iterations, uint64_t *data);

void benchmark_vpextrd(uint64_t iterations);
void benchmark_pextrq(uint64_t iterations);
void benchmark_vpextrq(uint64_t iterations);
void benchmark_pinsrq(uint64_t iterations);
void benchmark_vpinsrq(uint64_t iterations);
void benchmark_vpermq(uint64_t iterations);
void benchmark_vpshufb(uint64_t iterations);
void benchmark_bswap(uint64_t iterations);

void benchmark_read_p(uint64_t iterations, uint64_t *data);
void benchmark_write_p(uint64_t iterations, uint64_t *data);

#endif