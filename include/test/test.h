#ifndef _TEST_H_
#define _TEST_H_

#include "bcrypt.h"

void test_pass(const char *format, ...);

void test_fail(const char *format, ...);

void compare_states(blf_ctx *state_actual, blf_ctx *state_expected,
                    const char *test_name);

void do_test(uint64_t actual, uint64_t expected, const char *test_name);

void compare_ciphertexts(const char *actual, const char *expected,
                         const char *test_name, size_t ctext_bytes);

void compare_strings(const char *actual, const char *expected,
                     const char *test_name, size_t length);

#endif