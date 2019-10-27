/*
 * pbcrypt: parallel bcrypt for password cracking
 * Copyright (C) 2019  Catalina Juarros (catalinajuarros@protonmail.com)
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

#ifndef _TEST_H_
#define _TEST_H_

#include "bcrypt.h"

/*
 * Print success message.
 */
void test_pass(const char *format, ...);

/*
 * Print red error message and exit with failure status.
 */
void test_fail(const char *format, ...);

/*
 * Print pink start message.
 */
void test_start(const char *test_name, const char *args_format, ...);

/*
 * Compare Blowfish states, element by element.
 * Print success message if equal, exit with failure status if not.
 */
void compare_states(blf_ctx *state_actual, blf_ctx *state_expected,
                    const char *test_name);

/*
 * Compare two elements.
 * For internal usage in state comparison functions.
 */
void do_test(uint64_t actual, uint64_t expected, const char *test_name);

void compare_ciphertexts(const uint8_t *actual, const uint8_t *expected,
                         const char *test_name, size_t ctext_bytes);

void compare_strings(const char *actual, const char *expected,
                     const char *test_name, size_t length);

#endif