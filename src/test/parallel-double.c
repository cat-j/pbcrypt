#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bcrypt.h"
#include "bcrypt-constants.h"
#include "bcrypt-macro-testing.h"
#include "bcrypt-parallel-double.h"
#include "parallel-double-test-wrappers.h"
#include "openbsd.h"
#include "test.h"

void test_f_ymm(pd_blf_ctx *p_state, blf_ctx *state,
                uint32_t *bytes_actual, uint32_t *bytes_expected,
                const char *state_name)
{
    char test_name[] = "test_f_ymm";
    test_start(test_name, "bytes_actual: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x, "
        "p_state: %s",
        bytes_actual[0], bytes_actual[1], bytes_actual[2], bytes_actual[3],
        bytes_actual[4], bytes_actual[5], bytes_actual[6], bytes_actual[7],
        state_name);

    f_ymm(p_state, bytes_actual);
    
    uint32_t current_expected;

    for (size_t i = 0; i < DWORDS_PER_YMM; ++i) {
        current_expected = f_asm(bytes_expected[i], state);
        do_test(bytes_actual[i], current_expected, test_name);
    }
}

void test_blowfish_round_ymm(pd_blf_ctx *p_state, blf_ctx *state,
                             uint32_t *xl_actual, uint32_t *xr_actual,
                             uint32_t *xl_expected, uint32_t *xr_expected,
                             uint32_t n, const char *state_name)
{
    char test_name[] = "test_blowfish_round_ymm";
    test_start(test_name,
        "xl_actual: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x, "
        "xr_actual: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x, "
        "n: %d, p_state: %s",
        xl_actual[0], xl_actual[1], xl_actual[2], xl_actual[3],
        xl_actual[4], xl_actual[5], xl_actual[6], xl_actual[7],
        xr_actual[0], xr_actual[1], xr_actual[2], xr_actual[3],
        xr_actual[4], xr_actual[5], xr_actual[6], xr_actual[7],
        n, state_name);

    blowfish_round_ymm(p_state, xl_actual, xr_actual, n);
    
    uint32_t current_expected;

    for (size_t i = 0; i < DWORDS_PER_YMM; ++i) {
        current_expected = blowfish_round_asm(xl_expected[i], xr_expected[i],
            state, n);
        do_test(xr_actual[i], current_expected, test_name);
    }
}

void compare_parallelised_state(pd_blf_ctx *state_actual, blf_ctx *src,
                                size_t scale, const char *test_name)
{
    uint32_t *p_actual = state_actual->P, *p_src = src->P;
    uint32_t current_actual, current_expected;
    size_t k = 0;

    for (size_t i = 0; i < P_ARRAY_LENGTH; ++i) {
        current_expected = p_src[i];

        for (size_t j = 0; j < scale; ++j) {
            current_actual = p_actual[k];
            if (current_actual != current_expected) {
                test_fail("States in test %s differ. "
                    "P-element: %d, expected value: 0x%08x, actual value: 0x%08x\n",
                    test_name, i, current_expected, current_actual);
            }

            ++k;
        }
    }

    for (size_t i = 0; i < 4; ++i) {
        k = 0;

        for (size_t j = 0; j < S_BOX_LENGTH; ++j) {
            current_expected = src->S[i][j];

            for (size_t l = 0; l < scale; ++l) {
                current_actual = state_actual->S[i][k];
                if (current_actual != current_expected) {
                    test_fail("States in test %s differ. "
                        "S-box: %d, element: %d, "
                        "expected value: 0x%08x, actual value: 0x%08x\n",
                        test_name, i, j, current_expected, current_actual);
                }

                ++k;
            }
        }
    }

    test_pass("Success: states in %s are equal.\n", test_name);
}

void test_blowfish_parallelise_state(pd_blf_ctx *p_state, blf_ctx *src,
                                     size_t scale, const char *p_state_name,
                                     const char *src_name)
{
    char test_name[] = "test_blowfish_parallelise_state";
    test_start(test_name, "p_state: %s, src: %s, scale: %d",
        p_state_name, src_name, scale);

    blowfish_parallelise_state_double(p_state, src);

    compare_parallelised_state(p_state, src, scale, test_name);
}

void test_copy_ctext_ymm(uint8_t *data_actual, uint8_t *data_expected,
                         const uint8_t *ctext)
{
    char test_name[] = "test_copy_ctext_ymm";
    test_start(test_name, "ciphertext: %s", ctext);

    copy_ctext_ymm((uint64_t *) data_actual, ctext);
    copy_ctext_openbsd((uint32_t *) data_expected, (const char *) ctext,
        DWORDS_PER_YMM);

    compare_ciphertexts(data_actual, data_expected, test_name,
        BCRYPT_HASH_BYTES*DWORDS_PER_YMM);
}

void compare_p_states(pd_blf_ctx *state_actual, pd_blf_ctx *state_expected,
                      size_t scale, const char *test_name) {
    uint32_t *p_actual = state_actual->P, *p_expected = state_expected->P;
    uint32_t current_actual, current_expected;

    for (size_t i = 0; i < P_ARRAY_LENGTH*scale; ++i) {
        current_actual = p_actual[i];
        current_expected = p_expected[i];

        if (current_actual != current_expected) {
            test_fail("States in test %s differ. "
                "P-element: %d, expected value: 0x%08x, actual value: 0x%08x\n",
                test_name, i, current_expected, current_actual);
        }
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < S_BOX_LENGTH*scale; ++j) {
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

void compare_p_state_many(pd_blf_ctx *p_state, blf_ctx **states, size_t scale,
                          const char *test_name)
{
    uint32_t current_actual, current_expected;
    blf_ctx *current_state;

    for (size_t i = 0; i < scale; ++i) {
        current_state = states[i];

        for (size_t j = 0; j < 4; ++j) {
            for (size_t k = 0; k < S_BOX_LENGTH; ++k) {
                current_actual = p_state->S[j][scale*k + i];
                current_expected = current_state->S[j][k];
                if (current_actual != current_expected) {
                    test_fail("States in test %s differ. "
                        "State: %d, S-box: %d, element: %d, "
                        "expected value: 0x%08x, actual value: 0x%08x\n",
                        test_name, i, j, k, current_expected, current_actual);
                }
            }

            for (size_t j = 0; j < P_ARRAY_LENGTH; ++j) {
                current_actual = p_state->P[scale*j + i];
                current_expected = current_state->P[j];
                if (current_actual != current_expected) {
                    test_fail("States in test %s differ. "
                        "State: %d, P-element: %d, "
                        "expected value: 0x%08x, actual value: 0x%08x\n",
                        test_name, i, j, current_expected, current_actual);
                }
            }
        }
    }

    test_pass("Success: states in %s are equal.\n", test_name);
}

void test_blowfish_init_state_parallel(pd_blf_ctx *state_actual,
                                       pd_blf_ctx *state_expected,
                                       const char *p_state_name)
{
    char test_name[] = "test_blowfish_init_state_parallel";
    test_start(test_name, "p_state: %s", p_state_name);
    blowfish_init_state_parallel_double(state_actual, state_expected);
    compare_p_states(state_actual, state_expected, DWORDS_PER_YMM, test_name);
}

void test_blowfish_expand_state_parallel(pd_blf_ctx *p_state, blf_ctx **states,
                                         const uint8_t *salt, const char *keys,
                                         uint16_t keybytes, size_t scale,
                                         const char *p_state_name)
{
    char test_name[] = "test_blowfish_expand_state_parallel";
    test_start(test_name, "p_state: %s, salt: %s, keys: %s, keybytes: %d",
        p_state_name, salt, keys, keybytes);

    blowfish_expand_state_parallel_double_wrapper(p_state, salt, keys, keybytes);

    for (size_t i = 0; i < scale; ++i) {
        blowfish_expand_state_asm(states[i], salt, &keys[i*(keybytes)], keybytes);
    }

    compare_p_state_many(p_state, states, scale, test_name);
}

void test_blowfish_expand_0_state_parallel(pd_blf_ctx *p_state, blf_ctx **states,
                                           const char *keys, uint16_t keybytes,
                                           size_t scale, const char *p_state_name)
{
    char test_name[] = "test_blowfish_expand_0_state_parallel";
    test_start(test_name, "p_state: %s, keys: %s, keybytes: %d",
        p_state_name, keys, keybytes);

    blowfish_expand_0_state_parallel_double_wrapper(p_state, keys, keybytes);

    for (size_t i = 0; i < scale; ++i) {
        blowfish_expand_0_state_asm(states[i], &keys[i*(keybytes)], keybytes);
    }

    compare_p_state_many(p_state, states, scale, test_name);
}

void test_blowfish_expand_0_state_salt_parallel(pd_blf_ctx *p_state, blf_ctx **states,
                                                const uint8_t *salt, size_t scale,
                                                const char *p_state_name)
{
    char test_name[] = "test_blowfish_expand_0_state_salt_parallel";
    test_start(test_name, "p_state: %s, salt: %s",
        p_state_name, salt);
    
    blowfish_expand_0_state_salt_parallel_double_wrapper(p_state, salt);

    for (size_t i = 0; i < scale; ++i) {
        blowfish_expand_0_state_salt_asm(states[i], salt);
    }

    compare_p_state_many(p_state, states, scale, test_name);
}

void compare_p_ciphertexts(const uint8_t *actual, const uint8_t *expected,
                           size_t ctext_bytes, size_t scale,
                           const char *test_name)
{
    uint32_t *dwords_actual = (uint32_t *) actual;
    uint32_t *dwords_expected = (uint32_t *) expected;
    uint32_t current_actual, current_expected;
    size_t len = ctext_bytes >> 2; // dwords in single-data ciphertext

    // i is each dword index (0 to 6)
    // j is each ciphertext (0 to scale)
    for (size_t i = 0; i < len; ++i) {
        for (size_t j = 0; j < scale; ++j) {
            current_actual = dwords_actual[i*scale + j];
            current_expected = dwords_expected[j*len + i];
            
            if (current_actual != current_expected) {
                test_fail("Ciphertexts in test %s differ. "
                    "Ciphertext: %d, index: %d, "
                    "expected value: 0x%08x, actual value: 0x%08x\n",
                    test_name, j, i, current_expected, current_actual);
            }
        }
    }

    test_pass("Success: ciphertexts in %s are equal.\n", test_name);
}

void test_bcrypt_hashpass_parallel(pd_blf_ctx *p_state, blf_ctx **states,
                                   uint8_t *hashes_actual, uint8_t *hashes_expected,
                                   const char *keys, uint16_t keybytes,
                                   const uint8_t *salt, uint64_t rounds,
                                   size_t scale)
{
    char test_name[] = "test_bcrypt_hashpass_parallel";
    test_start(test_name, "salt: %s, keys: %s, rounds: %d", salt, keys, rounds);

    bcrypt_hashpass_parallel_double(p_state, salt, keys, keybytes, hashes_actual, rounds);

    for (size_t i = 0; i < scale; ++i) {
        bcrypt_hashpass(states[i], salt, &keys[i*keybytes],
            keybytes, &hashes_expected[i*BCRYPT_HASH_BYTES], rounds);
    }

    compare_p_state_many(p_state, states, scale, test_name);
    compare_p_ciphertexts(hashes_actual, hashes_expected,
        BCRYPT_HASH_BYTES, scale, test_name);

}

void test_bcrypt_hashpass() {
    // Parallel state
    pd_blf_ctx *p_state_actual;
    posix_memalign((void**) &p_state_actual, 32, sizeof(pd_blf_ctx));
    blowfish_parallelise_state_double(&initstate_parallel_double, &initstate_asm);
    
    // Single-data states
    blf_ctx **states = malloc(DWORDS_PER_YMM * sizeof(blf_ctx *)); // expected single-data states
    blf_ctx *current;
    // Align single-data states
    for (size_t i = 0; i < DWORDS_PER_YMM; ++i) {
        posix_memalign((void**) &current, 32, sizeof(blf_ctx));
        states[i] = current;
    }

    uint8_t salt[] = "opabiniaOPABINIA";
    char keys[] = "anomalocaris\0GoLandcrabs!\0ANOMALOCARIS\0goLANDCRABS!\0"
                  "jimmy mcgill\0saul goodman\0Jimmy McGill\0Saul Goodman\0";
    uint16_t keybytes = strlen(keys) / DWORDS_PER_YMM - 1;

    uint8_t hashes_actual[BCRYPT_HASH_BYTES*DWORDS_PER_YMM];
    uint8_t hashes_expected[BCRYPT_HASH_BYTES*DWORDS_PER_YMM];

    uint64_t rounds = 8;

    test_bcrypt_hashpass_parallel(p_state_actual, states, hashes_actual, hashes_expected,
        keys, keybytes, salt, rounds, DWORDS_PER_YMM);

    free(p_state_actual);
    for (size_t i = 0; i < DWORDS_PER_YMM; ++i) {
        free(states[i]);
    }
    free(states);
}

int main(int argc, char const *argv[]) {
    blf_ctx *src;
    pd_blf_ctx *state_expected;
    pd_blf_ctx *state_actual;

    posix_memalign((void**) &src, 32, sizeof(blf_ctx));
    posix_memalign((void**) &state_expected, 32, sizeof(pd_blf_ctx));
    posix_memalign((void**) &state_actual, 32, sizeof(pd_blf_ctx));

    Blowfish_initstate(src);

    test_blowfish_parallelise_state(state_expected, src, DWORDS_PER_YMM,
        "blank", "initial_state");

    test_blowfish_init_state_parallel(state_actual, state_expected, "initial_p_state");

    uint32_t bytes_actual[8] = {0xdeadbeef, 0x00c0ffee, 0xfeedbeef, 0x00faece5,
                                0xbeef1dad, 0xc001dadd, 0xbaddad61, 0xfeeeddad};
    uint32_t bytes_expected[8] = {0xdeadbeef, 0x00c0ffee, 0xfeedbeef, 0x00faece5,
                                  0xbeef1dad, 0xc001dadd, 0xbaddad61, 0xfeeeddad};
    
    test_f_ymm(state_actual, src, (uint32_t *) &bytes_actual,
        (uint32_t *) &bytes_expected, "initial_p_state");

    uint32_t xl_actual[8] = {0xdeadbeef, 0xfeedbeef, 0xbeefdead, 0xbeeffeed,
                             0xbeef1dad, 0xc001dadd, 0xbaddad61, 0xfeeeddad};

    uint32_t xr_actual[8] = {0xaac0ffee, 0xc0ffeeee, 0xc0ffffee, 0xc0ffee00,
                             0xbeef1dad, 0xc001dadd, 0xbaddad61, 0xfeeeddad};

    uint32_t xl_expected[8] = {0xdeadbeef, 0xfeedbeef, 0xbeefdead, 0xbeeffeed,
                               0xbeef1dad, 0xc001dadd, 0xbaddad61, 0xfeeeddad};

    uint32_t xr_expected[8] = {0xaac0ffee, 0xc0ffeeee, 0xc0ffffee, 0xc0ffee00,
                               0xbeef1dad, 0xc001dadd, 0xbaddad61, 0xfeeeddad};

    test_blowfish_round_ymm(state_actual, src, xl_actual, xr_actual,
        xl_expected, xr_expected, 1, "initial_state");

    blf_ctx **states = malloc(DWORDS_PER_YMM * sizeof(blf_ctx *)); // expected single-data states
    blf_ctx *current;
    
    // Initialise single-data states
    for (size_t i = 0; i < DWORDS_PER_YMM; ++i) {
        posix_memalign((void**) &current, 32, sizeof(blf_ctx));
        Blowfish_initstate(current);
        states[i] = current;
    }

    uint8_t salt[] = "opabiniaOPABINIA"; // 128 bits long
    char keys[] = "anomalocaris\0GoLandcrabs!\0ANOMALOCARIS\0goLANDCRABS!\0"
                  "jimmy mcgill\0saul goodman\0Jimmy McGill\0Saul Goodman\0";
    uint16_t keybytes = strlen(keys) + 1;

    uint8_t data_actual[BCRYPT_HASH_BYTES*DWORDS_PER_YMM];
    uint8_t data_expected[BCRYPT_HASH_BYTES*DWORDS_PER_YMM];

    test_blowfish_expand_state_parallel(state_actual, states,
        salt, keys, keybytes, DWORDS_PER_YMM, "initial_p_state");

    test_blowfish_expand_0_state_parallel(state_actual, states,
        keys, keybytes, DWORDS_PER_YMM, "expanded_p_state");

    test_blowfish_expand_0_state_salt_parallel(state_actual, states,
        salt, DWORDS_PER_YMM, "key_expanded_p_state");

    test_bcrypt_hashpass();

    test_copy_ctext_ymm(data_actual, data_expected, initial_pd_ctext);

    return 0;
}