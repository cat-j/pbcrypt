#include <assert.h>
// #include <malloc.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bcrypt.h"
#include "bcrypt-constants.h"
#include "bcrypt-macro-testing.h"
#include "cracker-common.h"
#include "loaded-p-test-wrappers.h" // TODO: make this optional
#include "openbsd.h"
#include "test.h"

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

void test_blowfish_expand_state_asm(blf_ctx *state_actual, blf_ctx *state_expected,
                                    const uint8_t *salt,
                                    const char *key, uint16_t keybytes,
                                    const char *state_name)
{
    char test_name[] = "test_blowfish_expand_state_asm";
    test_start(test_name, "state: %s, salt: %s, key: %s",
        state_name, salt, key);

    if (variant < 2) {
        blowfish_expand_state_asm(state_actual, salt, key, keybytes);
    } else {
        blowfish_expand_state_wrapper(state_actual, salt, key, keybytes);
    }

    Blowfish_expandstate(state_expected, (uint8_t *) salt, BCRYPT_SALT_BYTES,
                         (uint8_t *) key, keybytes);

    compare_states(state_actual, state_expected, test_name);
}

void test_blowfish_expand_0_state_asm(blf_ctx *state_actual, blf_ctx *state_expected,
                                      const uint8_t *salt,
                                      const char *key, uint16_t keybytes,
                                      const char *state_name)
{
    char test_name[] = "test_blowfish_expand_0_state_asm";
    test_start(test_name, "state: %s, key: %s", state_name, key);

    if (variant < 2) {
        blowfish_expand_0_state_asm(state_actual, key, keybytes);
    } else {
        blowfish_expand_0_state_wrapper(state_actual, salt, key, keybytes);
    }

    Blowfish_expand0state(state_expected, (uint8_t *) key, keybytes);

    compare_states(state_actual, state_expected, test_name);
}

void test_blowfish_expand_0_state_salt_asm(blf_ctx *state_actual, blf_ctx *state_expected,
                                           const uint8_t *salt, const char *key,
                                           uint16_t keybytes, const char *state_name)
{
    char test_name[] = "test_blowfish_expand_0_state_salt_asm";
    test_start(test_name, "state: %s, salt: %s", state_name, salt);

    if (variant < 2) {
        blowfish_expand_0_state_salt_asm(state_actual, salt);
    } else {
        blowfish_expand_0_state_salt_wrapper(state_actual, salt, key, keybytes);
    }

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

    compare_ciphertexts((uint8_t *) data_actual, (uint8_t *) data_expected,
        test_name, BCRYPT_HASH_BYTES);
}

void test_blowfish_encrypt_asm_rounds(const blf_ctx *state, uint8_t *data_actual,
                                      uint8_t *data_expected, uint16_t rounds,
                                      const char *state_name)
{
    char test_name[] = "test_blowfish_encrypt_asm_rounds";
    test_start(test_name, "state: %s, data: %s, rounds: %d", state_name,
        data_actual, rounds);

    for (size_t i = 0; i < rounds; ++i) {
        blowfish_encrypt_asm(state, (uint64_t *) data_actual);
        blf_enc(state, (uint32_t *) data_expected, BCRYPT_WORDS / 2);
    }

    compare_ciphertexts((uint8_t *) data_actual, (uint8_t *) data_expected,
        test_name, BCRYPT_HASH_BYTES);
}

void test_copy_ctext_asm(uint8_t *data_actual, uint8_t *data_expected,
                         const uint8_t *ctext)
{
    char test_name[] = "test_copy_ctext_asm";
    test_start(test_name, "ciphertext: %s", ctext);

    copy_ctext_asm((uint64_t *) data_actual, ctext);
    copy_ctext_openbsd((uint32_t *) data_expected, (char *) ctext, 1);

    compare_ciphertexts((uint8_t *) data_actual, (uint8_t *) data_expected,
        test_name, BCRYPT_HASH_BYTES);
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

void test_bcrypt_hashpass_asm(blf_ctx *state_actual, blf_ctx *state_expected,
                              uint8_t *hash_actual, uint8_t *hash_expected,
                              const char *key, uint16_t keybytes,
                              const uint8_t *salt, uint64_t rounds)
{
    char test_name[] = "test_bcrypt_hashpass_asm";
    test_start(test_name, "salt: %s, key: %s, rounds: %ld", salt, key, rounds);

    bcrypt_hashpass_asm(state_actual, salt, key, keybytes, hash_actual, rounds);
    bcrypt_hashpass(state_expected, key, (char *) salt, rounds, hash_expected);

    compare_states(state_actual, state_expected, test_name);
    compare_ciphertexts(hash_actual, hash_expected, test_name, BCRYPT_HASH_BYTES);
}

void test_bcrypt_hashpass() {
    blf_ctx *state_actual;
    blf_ctx *state_expected;

    posix_memalign((void**) &state_actual, 32, sizeof(blf_ctx));
    posix_memalign((void**) &state_expected, 32, sizeof(blf_ctx));

    uint8_t salt[] = "opabiniaOPABINIA"; // 128 bits long
    char key[] = "anomalocaris";
    uint16_t keybytes = strlen(key);

    uint8_t hash_actual[BCRYPT_HASH_BYTES];
    uint8_t hash_expected[BCRYPT_HASH_BYTES];

    uint64_t rounds = 8;

    test_bcrypt_hashpass_asm(state_actual, state_expected,
                             hash_actual, hash_expected,
                             key, keybytes, salt, rounds);

    free(state_actual);
    free(state_expected);
}

void test_get_record_data(char *record, uint8_t *ciphertext_actual,
                          uint8_t *salt_actual, uint64_t *rounds_actual,
                          uint8_t *ciphertext_expected, uint8_t *salt_expected,
                          uint64_t rounds_expected, int err_expected)
{
    char test_name[] = "test_get_record_data";
    test_start(test_name, "record: %s", record);

    int err_actual = get_record_data(record, ciphertext_actual, salt_actual,
                                     rounds_actual);

    do_test(err_actual, err_expected, "errtest");

    if (err_actual == 0) {
        do_test(*rounds_actual, rounds_expected, "roundstest");

        compare_ciphertexts(ciphertext_actual, ciphertext_expected,
                            test_name, 21);

        compare_strings((char *) salt_actual, (char *) salt_expected,
                        test_name, BCRYPT_SALT_BYTES);
    }
}

void test_get_record_data_all() {
    char record[] = "$2b$08$Z1/fWkjsYUDNSCDAQS3HOOWU3tZUDqZ0LfakjxOS3NRSDKRyL/Sij";
    uint8_t *ciphertext_actual = malloc(BCRYPT_HASH_BYTES);
    uint8_t *salt_actual = malloc(BCRYPT_SALT_BYTES);
    uint64_t rounds_actual;

    char ciphertext_expected[] = "anomalocarisANOMALOCARIS";
    char salt_expected[] = "opabiniaOPABINIA";
    uint64_t rounds_expected = 1U << 8;
    int err_expected = 0;

    test_get_record_data((char*) &record, ciphertext_actual, salt_actual,
                         &rounds_actual, (uint8_t *) &ciphertext_expected,
                         (uint8_t *) &salt_expected,
                         rounds_expected, err_expected);

    free(ciphertext_actual);
    free(salt_actual);
}

int main(int argc, char const *argv[]) {
    blf_ctx *state;
    blf_ctx *state_expected;

    posix_memalign((void**) &state, 32, sizeof(blf_ctx));
    posix_memalign((void**) &state_expected, 32, sizeof(blf_ctx));
    
    uint8_t salt[] = "opabiniaOPABINIA"; // 128 bits long
    char key[] = "anomalocaris";
    uint16_t keybytes = strlen(key);

    uint8_t data_actual[BCRYPT_HASH_BYTES];
    uint8_t data_expected[BCRYPT_HASH_BYTES];

    uint8_t final_data_actual[BCRYPT_HASH_BYTES];
    uint8_t final_data_expected[BCRYPT_HASH_BYTES];

    test_blowfish_init_state_asm(state, state_expected);
    test_blowfish_round_all(state, "initial_state");
    test_blowfish_encipher_asm_all(state, "initial_state");
    test_F_asm_all(state, "initial_state");

    test_blowfish_expand_state_asm(state, state_expected, salt,
        key, keybytes, "initial_state");

    test_blowfish_expand_0_state_asm(state, state_expected, salt,
        key, keybytes, "expanded_state");
    
    test_blowfish_expand_0_state_salt_asm(state, state_expected, salt,
        key, keybytes, "key_expanded_state");

    test_copy_ctext_asm(data_actual, data_expected, initial_ctext);

    if (variant < 2) {
        test_blowfish_encrypt_asm_rounds(state, data_actual, data_expected, 64,
            "expanded_0_state");
    }    

    test_copy_ctext_asm(final_data_actual, final_data_expected, data_actual);

    test_bcrypt_hashpass();

    test_get_record_data_all();
    
    free(state);
    free(state_expected);

    return 0;
}
