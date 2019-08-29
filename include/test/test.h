#ifndef _TEST_H_
#define _TEST_H_

#include "bcrypt.h"

void test_pass(const char *format, ...);

void test_fail(const char *format, ...);

void compare_states(blf_ctx *state_actual, blf_ctx *state_expected,
                    const char *test_name);

void do_test(uint64_t actual, uint64_t expected, const char *test_name);

#endif