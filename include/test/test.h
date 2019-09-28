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

void compare_ciphertexts(const char *actual, const char *expected,
                         const char *test_name, size_t ctext_bytes);

void compare_strings(const char *actual, const char *expected,
                     const char *test_name, size_t length);

#endif