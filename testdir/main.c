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

void test_blowfish_init_state_asm(blf_ctx *state_actual, blf_ctx *state_expected)
{
    char test_name[] = "test_blowfish_init_state_asm";
    test_start(test_name, "");

    blowfish_init_state_asm(state_actual);
    Blowfish_initstate(state_expected);

    compare_states(state_actual, state_expected, test_name);
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

    test_pass("%s successful.\n", test_name);
}

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

        if (current_actual != current_expected) {
            test_fail("Ciphertexts in test %s differ. "
                "Index: %d, expected value: 0x%08x, actual value: 0x%08x\n",
                test_name, i, current_expected, current_actual);
        }
    }

    test_pass("%s successful.\n", test_name);
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

    test_pass("%s successful.\n", test_name);
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
    Blowfish_expand0statesalt(state_expected, (uint8_t *) salt, BCRYPT_MAXSALT);

    compare_states(state_actual, state_expected, test_name);
}

void test_blowfish_encrypt_asm(const blf_ctx *state, char *data_actual,
                               char *data_expected, const char *state_name)
{
    char test_name[] = "test_blowfish_encrypt_asm";
    test_start(test_name, "state: %s, data: %s", state_name, data_actual);

    blowfish_encrypt_asm(state, (uint64_t *) data_actual);
    blf_enc(state, (uint32_t *) data_expected, BCRYPT_WORDS / 2);

    compare_ciphertexts(data_actual, data_expected, test_name, BCRYPT_WORDS << 2);
}

void test_blowfish_encrypt_asm_rounds(const blf_ctx *state, char *data_actual,
                                      char *data_expected, uint16_t rounds,
                                      const char *state_name)
{
    char test_name[] = "test_blowfish_encrypt_asm_rounds";
    test_start(test_name, "state: %s, data: %s, rounds: %d", state_name,
        data_actual, rounds);

    for (size_t i = 0; i < rounds; ++i) {
        blowfish_encrypt_asm(state, (uint64_t *) data_actual);
        blf_enc(state, (uint32_t *) data_expected, BCRYPT_WORDS / 2);
    }

    compare_ciphertexts(data_actual, data_expected, test_name, BCRYPT_WORDS << 2);
}

void test_copy_ctext_asm(char *data_actual, char *data_expected, const char *ctext) {
    char test_name[] = "test_copy_ctext_asm";
    test_start(test_name, "ciphertext: %s", ctext);

    copy_ctext_asm((uint64_t *) data_actual, ctext);
    copy_ctext_openbsd((uint32_t *) data_expected, ctext);

    compare_ciphertexts(data_actual, data_expected, test_name, BCRYPT_WORDS << 2);
}

void test_b64_encode(char *dst_actual, char *dst_expected, char *src,
                     uint64_t srcbytes, uint64_t dstbytes)
{
    char test_name[] = "test_b64_encode";
    test_start(test_name, "src: %s", src);

    b64_encode(dst_actual, src, srcbytes);

    compare_strings(dst_actual, dst_expected, test_name, dstbytes);
}

void test_b64_decode(char *dst_actual, char *dst_expected, char *src,
                     uint64_t srcbytes, uint64_t dstbytes)
{
    char test_name[] = "test_b64_decode";
    test_start(test_name, "src: %s", src);

    b64_decode(dst_actual, src, srcbytes);

    compare_strings(dst_actual, dst_expected, test_name, dstbytes);
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

void test_b64_encode_all() {
    char *dst_actual = malloc(12);
    test_b64_encode(dst_actual, "b3BhYmluaWE=", "opabinia", 8, 12);
    test_b64_encode(dst_actual, "d2l3YXhpYQ==", "wiwaxia", 7, 12);
    free(dst_actual);

    dst_actual = malloc(16);
    test_b64_encode(dst_actual, "YW5vbWFsb2Nhcmlz", "anomalocaris", 12, 16);
    free(dst_actual);
}

void test_b64_decode_all() {
    char *dst_actual = malloc(8);
    test_b64_decode(dst_actual, "opabinia", "b3BhYmluaWE=", 12, 8);
    free(dst_actual);

    dst_actual = malloc(7);
    test_b64_decode(dst_actual, "wiwaxia", "d2l3YXhpYQ==", 12, 7);
    free(dst_actual);

    dst_actual = malloc(12);
    test_b64_decode(dst_actual, "anomalocaris", "YW5vbWFsb2Nhcmlz", 16, 12);
    free(dst_actual);
}

void test_bcrypt_core() {
    char key[] = "anomalocaris";
    char salt[] = "opabiniaOPABINIA";

    bcrypt_hashpass((const char *) &key, (const char *) &salt);
}

int main(int argc, char const *argv[]) {
    test_reverse_bytes(0xdeadbeefaac0ffee, 0xeeffc0aaefbeadde);

    test_b64_encode_all();
    test_b64_decode_all();

    blf_ctx *state;
    blf_ctx *state_expected;

    posix_memalign((void**) &state, 32, sizeof(blf_ctx));
    posix_memalign((void**) &state_expected, 32, sizeof(blf_ctx));
    
    char salt[] = "opabiniaOPABINIA"; // 128 bits long
    char key[] = "anomalocaris";
    uint16_t saltbytes = strlen(salt);
    uint16_t keybytes = strlen(key);

    char data_actual[BCRYPT_WORDS << 2];
    char data_expected[BCRYPT_WORDS << 2];

    char final_data_actual[BCRYPT_WORDS << 2];
    char final_data_expected[BCRYPT_WORDS << 2];

    test_blowfish_init_state_asm(state, state_expected);
    
    test_blowfish_round_all(state, "initial_state");
    test_blowfish_encipher_asm_all(state, "initial_state");
    test_F_asm_all(state, "initial_state");

    test_blowfish_expand_state_asm(state, state_expected, salt, saltbytes,
        key, keybytes, "initial_state");

    test_blowfish_expand_0_state_asm(state, state_expected, key, keybytes,
        "expanded_state");
    
    test_blowfish_expand_0_state_salt_asm(state, state_expected, salt,
        "key_expanded_state");

    test_copy_ctext_asm(data_actual, data_expected, (const char *) initial_ctext);
    
    test_blowfish_encrypt_asm_rounds(state, data_actual, data_expected, 64,
        "expanded_0_state");

    test_copy_ctext_asm(final_data_actual, final_data_expected, data_actual);

    // test_bcrypt_core();
    
    free(state);
    free(state_expected);

    return 0;
}
