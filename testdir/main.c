#include <assert.h>
// #include <malloc.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openbsd.h"
#include "test.h"
#include "../src/bcrypt.h" // TODO: figure out how to make "bcrypt.h" work
#include "../src/bcrypt_constants.h"

// TODO: replace "initial_state" with a parameter
// TODO: refactor these two functions
// void do_test(uint32_t actual, uint32_t expected, const char *test_name,
//              const char *args_format, ...)
// {
//     // Construct args string
//     char out[4096];
//     va_list args;
//     va_start(args, args_format);
//     vsnprintf(out, sizeof(out), args_format, args);

//     // Print test info: "Running test test_name with arguments args"
//     fprintf(stdout, "\n");
//     fprintf(stdout, "\033[1;35m");
//     fprintf(stdout, "Running test %s with arguments ", test_name);
//     fprintf(stdout, "%s\n", out);
//     fprintf(stdout, "\033[0m");

//     // Test
//     if (actual == expected) {
//         test_pass("%s successful.\n", test_name);
//     } else {
//         test_fail("%s failed.\n"
//         "Expected: 0x%08x\tActual: 0x%08x\n", test_name, expected, actual);
//     }
// }

void do_test(uint64_t actual, uint64_t expected, const char *test_name,
             const char *args_format, ...)
{
    // Construct args string
    char out[4096];
    va_list args;
    va_start(args, args_format);
    vsnprintf(out, sizeof(out), args_format, args);

    // Print test info: "Running test test_name with arguments args"
    fprintf(stdout, "\n");
    fprintf(stdout, "\033[1;35m");
    fprintf(stdout, "Running test %s with arguments ", test_name);
    fprintf(stdout, "%s\n", out);
    fprintf(stdout, "\033[0m");

    // Test
    if (actual == expected) {
        test_pass("%s successful.\n", test_name);
    } else {
        test_fail("%s failed.\n"
        "Expected: 0x%08x\tActual: 0x%08x\n", test_name, expected, actual);
    }
}

/* Prints success message */
void test_pass(const char *format, ...) {
    char out[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(out, sizeof(out), format, args);
    fprintf(stdout, "\033[1;32m");
    fprintf(stdout, "%s", out);
    fprintf(stdout, "\033[0m");
    va_end(args);
}

/* Prints red error message and exits */
void test_fail(const char *format, ...) {
    char out[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(out, sizeof(out), format, args);
    fprintf(stderr, "\033[1;31m");
    fprintf(stderr, "%s", out);
    fprintf(stderr, "\033[0m");
    va_end(args);
    exit(EXIT_FAILURE);
}

void test_blowfish_init_state_asm() {
    blf_ctx *expected, *actual;
    posix_memalign((void**) &expected, 32, sizeof(blf_ctx));
    posix_memalign((void**) &actual, 32, sizeof(blf_ctx));

    Blowfish_initstate(expected);
    blowfish_init_state_asm(actual);

    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < S_BOX_LENGTH; ++j) {
            if (expected->S[i][j] != actual->S[i][j]) {
                free(expected);
                free(actual);
                test_fail("test_blowfish_init_state_asm failed.\n"
                    "S-box: %ld\tElement: %ld\n", i, j);
            }
        }
    }

    for (size_t i = 0; i < P_ARRAY_LENGTH; ++i) {
        if (expected->P[i] != actual->P[i]) {
            free(expected);
            free(actual);
            test_fail("test_blowfish_init_state_asm failed.\n"
                "P-array element: %ld\n", i);
        }
    }

    free(expected);
    free(actual);
    test_pass("test_blowfish_init_state_asm successful.\n");
}

void test_F_asm(uint32_t x, const blf_ctx *state) {
    uint32_t actual = f_asm(x, state);
    uint32_t expected = f_wrapper(x, state);
    
    do_test(actual, expected, "test_F_asm", "%08x, %s", x, "initial_state");
}

void test_reverse_bytes(uint64_t data, uint64_t expected) {
    uint64_t actual = reverse_bytes(data);

    do_test(actual, expected, "test_reverse_bytes", "data: 0x%016lx", data);
}

void test_blowfish_round_asm(uint32_t xl, uint32_t xr, const blf_ctx *state,
                             uint32_t n)
{
    uint32_t actual = blowfish_round_asm(xl, xr, state, n);
    uint32_t expected = blfrnd_wrapper(state, xl, xr, n);

    do_test(actual, expected, "test_blowfish_round_asm",
        "xl: %08x, xr: %08x, state: %s, n: %ld", xl, xr, "initial_state", n);
}

void test_blowfish_encipher_asm(const blf_ctx *state, uint64_t data) {
    uint32_t xl_expected = data >> 32, xr_expected = data & 0xffffffff;
    uint64_t data_actual = data;

    blowfish_encipher_asm(state, &data_actual);
    Blowfish_encipher(state, &xl_expected, &xr_expected);

    uint64_t data_expected = (uint64_t) xr_expected;
    data_expected |= (uint64_t) xl_expected << 32;

    do_test(data_actual, data_expected, "test_blowfish_encipher_asm",
        "data: 0x%016lx, state: %s", data, "initial_state");
}

void test_blowfish_expand_state_asm(blf_ctx *state_actual, blf_ctx *state_expected,
                                    const char *salt, uint16_t saltbytes,
                                    const char *key, uint16_t keybytes)
{
    blowfish_expand_state_asm(state_actual, salt, saltbytes, key, keybytes);
    Blowfish_expandstate(state_expected, (uint8_t *) salt, saltbytes, (uint8_t *) key, keybytes);

    uint32_t *p_actual = state_actual->P;
    uint32_t *p_expected = state_expected->P;
    uint32_t current_actual, current_expected;

    for (size_t i = 0; i < P_ARRAY_LENGTH; ++i) {
        current_actual = p_actual[i];
        current_expected = p_expected[i];
        do_test(current_actual, current_expected, "test_blowfish_expand_state_asm",
            "salt: %s, key: %s, index: %ld",
            salt, key, i);
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < S_BOX_LENGTH; ++j) {
            current_actual = state_actual->S[i][j];
            current_expected = state_expected->S[i][j];
            do_test(current_actual, current_expected, "test_blowfish_expand_state_asm",
                "salt: %s, key: %s, box: %ld, index: %ld",
                salt, key, i, j);
        }
    }
}

void test_blowfish_expand_0_state_asm(blf_ctx *state_actual, blf_ctx *state_expected,
                                      const char *key, uint16_t keybytes)
{
    blowfish_expand_0_state_asm(state_actual, key, keybytes);
    Blowfish_expand0state(state_expected, (uint8_t *) key, keybytes);

    uint32_t *p_actual = state_actual->P;
    uint32_t *p_expected = state_expected->P;
    uint32_t current_actual, current_expected;

    for (size_t i = 0; i < P_ARRAY_LENGTH; ++i) {
        current_actual = p_actual[i];
        current_expected = p_expected[i];
        do_test(current_actual, current_expected, "test_blowfish_expand_0_state_asm",
            "key: %s, index: %ld", key, i);
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < S_BOX_LENGTH; ++j) {
            current_actual = state_actual->S[i][j];
            current_expected = state_expected->S[i][j];
            do_test(current_actual, current_expected, "test_blowfish_expand_0_state_asm",
                "key: %s, box: %ld, index: %ld", key, i, j);
        }
    }
}

int main(int argc, char const *argv[]) {
    // test_blowfish_init_state_asm();

    blf_ctx *state;
    blf_ctx *state_expected;

    posix_memalign((void**) &state, 32, sizeof(blf_ctx));
    posix_memalign((void**) &state_expected, 32, sizeof(blf_ctx));

    Blowfish_initstate(state);
    Blowfish_initstate(state_expected);
    
    test_F_asm(0x00000000, state);
    test_F_asm(0x11111111, state);
    test_F_asm(0x22222222, state);
    test_F_asm(0x33333333, state);
    test_F_asm(0x44444444, state);
    test_F_asm(0x55555555, state);
    test_F_asm(0x66666666, state);
    test_F_asm(0x77777777, state);
    test_F_asm(0x88888888, state);
    test_F_asm(0x99999999, state);
    test_F_asm(0xffffffff, state);
    test_F_asm(0x01010101, state);
    test_F_asm(0xf0f0f0f0, state);
    test_F_asm(0xdeadbeef, state);
    test_F_asm(0x12345678, state);
    test_F_asm(0x20002000, state);
    test_F_asm(0x00c0ffee, state);

    test_blowfish_round_asm(0xdeadbeef, 0x00c0ffee, state, 1);
    test_blowfish_round_asm(0xdeadbeef, 0x00c0ffee, state, 2);
    test_blowfish_round_asm(0xdeadbeef, 0x00c0ffee, state, 3);
    test_blowfish_round_asm(0xdeadbeef, 0x00c0ffee, state, 4);
    test_blowfish_round_asm(0xffffffff, 0xffffffff, state, 1);
    test_blowfish_round_asm(0xffffffff, 0xffffffff, state, 2);
    test_blowfish_round_asm(0xffffffff, 0x00000000, state, 1);
    test_blowfish_round_asm(0xffffffff, 0x00000000, state, 2);

    test_blowfish_encipher_asm(state, 0xdeadbeef00c0ffee);
    test_blowfish_encipher_asm(state, 0xdeadbeefdeadbeef);
    test_blowfish_encipher_asm(state, 0x00c0ffee00c0ffee);
    test_blowfish_encipher_asm(state, 0xffffffffffffffff);
    test_blowfish_encipher_asm(state, 0x0123456789abcdef);

    char salt[] = "opabiniaOPABINIA"; // 128 bits long
    char key[] = "anomalocaris";
    uint16_t saltbytes = strlen(salt);
    uint16_t keybytes = strlen(key);

    test_reverse_bytes(0xdeadbeefaac0ffee, 0xeeffc0aaefbeadde);

    test_blowfish_expand_state_asm(state, state_expected, salt, saltbytes,
        key, keybytes);

    test_blowfish_expand_0_state_asm(state, state_expected, key, keybytes);
    
    free(state);
    free(state_expected);

    return 0;
}
