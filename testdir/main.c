#include <assert.h>
// #include <malloc.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openbsd.h"
#include "test.h"
#include "../src/bcrypt.h" // TODO: figure out how to make "bcrypt.h" work
#include "../src/bcrypt_constants.h"

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
    fprintf(stdout, "\n");
    fprintf(stdout, "\033[1;35m");
    fprintf(stdout, "Running test %s with arguments ", test_name);
    fprintf(stdout, "%s\n", out);
    fprintf(stdout, "\033[0m");
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
    char test_name[] = "test_blowfish_init_state_asm";
    test_start(test_name, "");

    blf_ctx *expected, *actual;
    posix_memalign((void**) &expected, 32, sizeof(blf_ctx));
    posix_memalign((void**) &actual, 32, sizeof(blf_ctx));

    Blowfish_initstate(expected);
    blowfish_init_state_asm(actual);

    compare_states(actual, expected, test_name);

    free(expected);
    free(actual);
}

void test_F_asm(uint32_t x, const blf_ctx *state, const char *state_name) {
    char test_name[] = "test_F_asm";
    test_start(test_name, "x: 0x%08x, state: %s", x, state_name);

    uint32_t actual = f_asm(x, state);
    uint32_t expected = f_wrapper(x, state);
    
    do_test(actual, expected, test_name);
}

void test_reverse_bytes(uint64_t data, uint64_t expected)
{
    char test_name[] = "test_reverse_bytes";
    test_start(test_name, "data: 0x%016lx", data);

    uint64_t actual = reverse_bytes(data);

    do_test(actual, expected, test_name);
}

void test_blowfish_round_asm(uint32_t xl, uint32_t xr, const blf_ctx *state,
                             uint32_t n, const char *state_name)
{
    char test_name[] = "test_blowfish_round_asm";
    test_start(test_name, "xl: 0x%08x, xr: 0x%08x, state: %s, n: %ld",
        xl, xr, state_name, n);

    uint32_t actual = blowfish_round_asm(xl, xr, state, n);
    uint32_t expected = blfrnd_wrapper(state, xl, xr, n);

    do_test(actual, expected, test_name);
}

void test_blowfish_encipher_asm(const blf_ctx *state, uint64_t data,
                                const char *state_name)
{
    char test_name[] = "test_blowfish_encipher_asm";
    test_start(test_name, "data: 0x%016lx, state: %s", data, state_name);

    uint32_t xl_expected = data >> 32, xr_expected = data & 0xffffffff;
    uint64_t data_actual = data;

    blowfish_encipher_asm(state, &data_actual);
    Blowfish_encipher(state, &xl_expected, &xr_expected);

    uint64_t data_expected = (uint64_t) xr_expected;
    data_expected |= (uint64_t) xl_expected << 32;

    do_test(data_actual, data_expected, test_name);
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

    test_pass("%s passed.\n", test_name);
}

void compare_ciphertexts(const char *actual, const char *expected,
                         const char *test_name)
{
    uint32_t *dwords_actual = (uint32_t *) actual;
    uint32_t *dwords_expected = (uint32_t *) expected;
    uint32_t current_actual, current_expected;
    size_t len = strlen(actual) >> 2;

    for (size_t i = 0; i < len; ++i) {
        current_actual = dwords_actual[i];
        current_expected = dwords_expected[i];

        if (current_actual != current_expected) {
            test_fail("Ciphertexts in test %s differ. "
                "Index: %d, expected value: 0x%08x, actual value: 0x%08x\n",
                test_name, i, current_expected, current_actual);
        }
    }

    test_pass("%s passed.\n", test_name);
}

void test_blowfish_expand_state_asm(blf_ctx *state_actual, blf_ctx *state_expected,
                                    const char *salt, uint16_t saltbytes,
                                    const char *key, uint16_t keybytes,
                                    const char *state_name)
{
    char test_name[] = "test_blowfish_expand_state_asm";
    test_start(test_name, "state: %s, salt: %s, key: %s",
        state_name, salt, key);

    blowfish_expand_state_asm(state_actual, salt, saltbytes, key, keybytes);
    Blowfish_expandstate(state_expected, (uint8_t *) salt, saltbytes,
                         (uint8_t *) key, keybytes);

    compare_states(state_actual, state_expected, test_name);
}

void test_blowfish_expand_0_state_asm(blf_ctx *state_actual, blf_ctx *state_expected,
                                      const char *key, uint16_t keybytes,
                                      const char *state_name)
{
    char test_name[] = "test_blowfish_expand_0_state_asm";
    test_start(test_name, "state: %s, key: %s", state_name, key);

    blowfish_expand_0_state_asm(state_actual, key, keybytes);
    Blowfish_expand0state(state_expected, (uint8_t *) key, keybytes);

    compare_states(state_actual, state_expected, test_name);
}

void test_blowfish_expand_0_state_salt_asm(blf_ctx *state_actual, blf_ctx *state_expected,
                                      const char *salt, const char *state_name)
{
    char test_name[] = "test_blowfish_expand_0_state_salt_asm";
    test_start(test_name, "state: %s, salt: %s", state_name, salt);

    blowfish_expand_0_state_salt_asm(state_actual, salt);
    Blowfish_expand0statesalt(state_expected, (uint8_t *) salt, 16);

    compare_states(state_actual, state_expected, test_name);
}

void test_blowfish_encrypt_asm(const blf_ctx *state, char *data_actual,
                               char *data_expected, const char *state_name)
{
    // Make sure both functions receive the same input
    assert(strlen(data_actual) == strlen(data_expected));
    for (size_t i = 0; i < strlen(data_actual); ++i) {
        assert(data_actual[i] == data_expected[i]);
    }
    
    char test_name[] = "test_blowfish_encrypt_asm";
    test_start(test_name, "state: %s, data: %s", state_name, data_actual);

    blowfish_encrypt_asm(state, (uint64_t *) data_actual);
    blf_enc(state, (uint32_t *) data_expected, BCRYPT_WORDS / 2);

    compare_ciphertexts(data_actual, data_expected, test_name);
}

void test_copy_ctext_asm(char *data_actual, char *data_expected) {
    char test_name[] = "test_copy_ctext_asm";
    test_start(test_name, "ciphertext: %s", initial_ctext);

    copy_ctext_asm((uint64_t *) data_actual);
    copy_ctext_openbsd((uint32_t *) data_expected);

    compare_ciphertexts(data_actual, data_expected, "test_copy_ctext_asm");
}

void test_F_asm_all(blf_ctx *state, const char *state_name) {
    test_F_asm(0x00000000, state, state_name);
    test_F_asm(0x11111111, state, state_name);
    test_F_asm(0x22222222, state, state_name);
    test_F_asm(0x33333333, state, state_name);
    test_F_asm(0x44444444, state, state_name);
    test_F_asm(0x55555555, state, state_name);
    test_F_asm(0x66666666, state, state_name);
    test_F_asm(0x77777777, state, state_name);
    test_F_asm(0x88888888, state, state_name);
    test_F_asm(0x99999999, state, state_name);
    test_F_asm(0xffffffff, state, state_name);
    test_F_asm(0x01010101, state, state_name);
    test_F_asm(0xf0f0f0f0, state, state_name);
    test_F_asm(0xdeadbeef, state, state_name);
    test_F_asm(0x12345678, state, state_name);
    test_F_asm(0x20002000, state, state_name);
    test_F_asm(0x00c0ffee, state, state_name);
}

void test_blowfish_round_all(blf_ctx *state, const char *state_name) {
    test_blowfish_round_asm(0xdeadbeef, 0x00c0ffee, state, 1, state_name);
    test_blowfish_round_asm(0xdeadbeef, 0x00c0ffee, state, 2, state_name);
    test_blowfish_round_asm(0xdeadbeef, 0x00c0ffee, state, 3, state_name);
    test_blowfish_round_asm(0xdeadbeef, 0x00c0ffee, state, 4, state_name);
    test_blowfish_round_asm(0xffffffff, 0xffffffff, state, 1, state_name);
    test_blowfish_round_asm(0xffffffff, 0xffffffff, state, 2, state_name);
    test_blowfish_round_asm(0xffffffff, 0x00000000, state, 1, state_name);
    test_blowfish_round_asm(0xffffffff, 0x00000000, state, 2, state_name);
}

void test_blowfish_encipher_asm_all(blf_ctx *state, const char *state_name) {
    test_blowfish_encipher_asm(state, 0xdeadbeef00c0ffee, state_name);
    test_blowfish_encipher_asm(state, 0xdeadbeefdeadbeef, state_name);
    test_blowfish_encipher_asm(state, 0x00c0ffee00c0ffee, state_name);
    test_blowfish_encipher_asm(state, 0xffffffffffffffff, state_name);
    test_blowfish_encipher_asm(state, 0x0123456789abcdef, state_name);
}

void test_bcrypt_core() {
    char salt[] = "opabiniaOPABINIA";
    char key[] = "anomalocaris";

    int result = bcrypt_hashpass(&key, &salt);
}

int main(int argc, char const *argv[]) {
    test_blowfish_init_state_asm();

    blf_ctx *state;
    blf_ctx *state_expected;

    posix_memalign((void**) &state, 32, sizeof(blf_ctx));
    posix_memalign((void**) &state_expected, 32, sizeof(blf_ctx));

    test_F_asm_all(state, "initial_state");
    test_blowfish_round_all(state, "initial_state");
    test_blowfish_encipher_asm_all(state, "initial_state");

    Blowfish_initstate(state);
    Blowfish_initstate(state_expected);
    
    char salt[] = "opabiniaOPABINIA"; // 128 bits long
    char key[] = "anomalocaris";
    uint16_t saltbytes = strlen(salt);
    uint16_t keybytes = strlen(key);

    test_reverse_bytes(0xdeadbeefaac0ffee, 0xeeffc0aaefbeadde);

    test_blowfish_expand_state_asm(state, state_expected, salt, saltbytes,
        key, keybytes, "initial_state");

    test_blowfish_expand_0_state_asm(state, state_expected, key, keybytes,
        "expanded_state");
    
    test_blowfish_expand_0_state_salt_asm(state, state_expected, salt,
        "key_expanded_state");

    char data_actual[24];
    char data_expected[24];

    test_copy_ctext_asm(data_actual, data_expected);
    test_blowfish_encrypt_asm(state, data_actual, data_expected, "expanded_0_state");

    // test_bcrypt_core();
    
    free(state);
    free(state_expected);

    return 0;
}
