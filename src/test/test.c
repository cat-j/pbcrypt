#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "print.h"
#include "test.h"

void do_test(uint64_t actual, uint64_t expected, const char *test_name) {
    if (actual == expected) {
        test_pass("%s successful.\n", test_name);
    } else {
        test_fail("%s failed.\n"
        "Expected: 0x%08x\tActual: 0x%08x\n", test_name, expected, actual);
    }
}

void test_start(const char *test_name, const char *args_format, ...) {
    // Construct args string
    char out[4096];
    va_list args;
    va_start(args, args_format);
    vsnprintf(out, sizeof(out), args_format, args);

    // Print test info: "Running test test_name with arguments args"
    fprintf(stdout, BOLD_MAGENTA("\nRunning test %s with arguments "), test_name);
    fprintf(stdout, BOLD_MAGENTA("%s\n"), out);
}

void test_pass(const char *format, ...) {
    char out[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(out, sizeof(out), format, args);
    fprintf(stdout, BOLD_GREEN("%s"), out);
    va_end(args);
}

void test_fail(const char *format, ...) {
    char out[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(out, sizeof(out), format, args);
    fprintf(stderr, BOLD_RED("%s"), out);
    va_end(args);
    exit(EXIT_FAILURE);
}


void compare_states(blf_ctx *state_actual, blf_ctx *state_expected,
                    const char *test_name) {
    uint32_t *p_actual = state_actual->P, *p_expected = state_expected->P;
    uint32_t current_actual, current_expected;

    for (size_t i = 0; i < P_ARRAY_LENGTH; ++i) {
        current_actual = p_actual[i];
        current_expected = p_expected[i];
        if (current_actual != current_expected) {
            test_fail("States in test %s differ. "
                "P-element: %d, expected value: 0x%08x, actual value: 0x%08x\n",
                test_name, i, current_expected, current_actual);
        }
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < S_BOX_LENGTH; ++j) {
            current_actual = state_actual->S[i][j];
            current_expected = state_expected->S[i][j];
            if (current_actual != current_expected) {
                test_fail("States in test %s differ. "
                    "S-box: %d, element: %d, "
                    "expected value: 0x%08x, actual value: 0x%08x\n",
                    test_name, i, j, current_expected, current_actual);
            }
        }
    }

    test_pass("Success: states in %s are equal.\n", test_name);
}

// TODO: look into refactoring the following two functions

void compare_ciphertexts(const char *actual, const char *expected,
                         const char *test_name, size_t ctext_bytes)
{
    uint32_t *dwords_actual = (uint32_t *) actual;
    uint32_t *dwords_expected = (uint32_t *) expected;
    uint32_t current_actual, current_expected;
    size_t len = ctext_bytes >> 2;

    for (size_t i = 0; i < len; ++i) {
        current_actual = dwords_actual[i];
        current_expected = dwords_expected[i];
        // printf("actual: 0x%08x\texpected: 0x%08x\n", current_actual, current_expected);

        if (current_actual != current_expected) {
            test_fail("Ciphertexts in test %s differ. "
                "Index: %d, expected value: 0x%08x, actual value: 0x%08x\n",
                test_name, i, current_expected, current_actual);
        }
    }

    test_pass("Success: ciphertexts in %s are equal.\n", test_name);
}

void compare_strings(const char *actual, const char *expected,
                     const char *test_name, size_t length)
{
    char current_actual, current_expected;
    for (size_t i = 0; i < length; ++i) {
        current_actual = actual[i];
        current_expected = expected[i];

        if (current_actual != current_expected) {
            test_fail("Strings in test %s differ. "
                "Index: %d, expected value: %c, actual value: %c\n",
                test_name, i, current_expected, current_actual);
        }
    }

    test_pass("Success: strings in %s are equal.\n", test_name);
}