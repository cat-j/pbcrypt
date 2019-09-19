#include <stdio.h>
#include <stdlib.h>

#include "bcrypt.h"
#include "bcrypt-constants.h"
#include "bcrypt-macro-testing.h"
#include "bcrypt-parallel.h"
#include "openbsd.h"
#include "test.h"

#define DWORDS_PER_XMM 4


void test_f_xmm(p_blf_ctx *p_state, blf_ctx *state,
                uint32_t *bytes_actual, uint32_t *bytes_expected)
{
    char test_name[] = "test_f_xmm";
    f_xmm(p_state, bytes_actual);
    uint32_t current_expected;

    for (size_t i = 0; i < DWORDS_PER_XMM; ++i) {
        current_expected = f_asm(bytes_expected[i], state);
        do_test(bytes_actual[i], current_expected, test_name);
    }
}

void test_blowfish_round_xmm(p_blf_ctx *p_state, blf_ctx *state,
                             uint32_t *xl_actual, uint32_t *xr_actual,
                             uint32_t *xl_expected, uint32_t *xr_expected,
                             uint32_t n)
{
    char test_name[] = "test_blowfish_round_xmm";
    blowfish_round_xmm(p_state, xl_actual, xr_actual, n);
    uint32_t current_expected;

    for (size_t i = 0; i < DWORDS_PER_XMM; ++i) {
        current_expected = blowfish_round_asm(xl_expected[i], xr_expected[i],
            state, n);
        do_test(xr_actual[i], current_expected, test_name);
    }
}

void test_blowfish_parallelise_state(p_blf_ctx *state_actual, blf_ctx *src,
                                     size_t scale)
{
    char test_name[] = "test_blowfish_parallelise_state";
    test_start(test_name, "");

    blowfish_parallelise_state(state_actual, src);

    compare_parallelised_state(state_actual, src, scale, test_name);
}

void test_copy_ctext_xmm(char *data_actual, char *data_expected,
                         const char *ctext)
{
    char test_name[] = "test_copy_ctext_xmm";
    test_start(test_name, "ciphertext: %s", ctext);

    copy_ctext_xmm((uint64_t *) data_actual, ctext);
    copy_ctext_openbsd((uint32_t *) data_expected, ctext, DWORDS_PER_XMM);

    compare_ciphertexts(data_actual, data_expected, test_name,
        BCRYPT_HASH_BYTES*DWORDS_PER_XMM);
}

void compare_parallelised_state(p_blf_ctx *state_actual, blf_ctx *src,
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

void compare_p_states(p_blf_ctx *state_actual, p_blf_ctx *state_expected,
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

void compare_p_state_many(p_blf_ctx *p_state, blf_ctx **states, size_t scale,
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

void test_blowfish_init_state_parallel(p_blf_ctx *state_actual,
                                       p_blf_ctx *state_expected)
{
    char test_name[] = "test_blowfish_init_state_parallel";
    test_start(test_name, "");
    blowfish_init_state_parallel(state_actual, state_expected);
    compare_p_states(state_actual, state_expected, DWORDS_PER_XMM, test_name);
}

void test_blowfish_expand_state_parallel(p_blf_ctx *p_state, blf_ctx **states,
                                         const char *salt, const char *keys,
                                         uint64_t keybytes, size_t scale)
{
    char test_name[] = "test_blowfish_expand_state_parallel";
    blowfish_expand_state_parallel(p_state, salt, keys, keybytes);

    for (size_t i = 0; i < scale; ++i) {
        blowfish_expand_state_asm(states[i], salt, &keys[i*keybytes], keybytes);
    }

    compare_p_state_many(p_state, states, scale, test_name);
}

void test_blowfish_expand_0_state_parallel(p_blf_ctx *p_state, blf_ctx **states,
                                           const char *keys, uint64_t keybytes,
                                           size_t scale)
{
    char test_name[] = "test_blowfish_expand_0_state_parallel";
    blowfish_expand_0_state_parallel(p_state, keys, keybytes);

    for (size_t i = 0; i < scale; ++i) {
        blowfish_expand_0_state_asm(states[i], &keys[i*keybytes], keybytes);
    }

    compare_p_state_many(p_state, states, scale, test_name);
}

void test_blowfish_expand_0_state_salt_parallel(p_blf_ctx *p_state, blf_ctx **states,
                                                const char *salt, size_t scale)
{
    char test_name[] = "test_blowfish_expand_0_state_salt_parallel";
    blowfish_expand_0_state_salt_parallel(p_state, salt);

    for (size_t i = 0; i < scale; ++i) {
        blowfish_expand_0_state_salt_asm(states[i], salt);
    }

    compare_p_state_many(p_state, states, scale, test_name);
}

void compare_p_ciphertexts(const char *actual, const char *expected,
                           size_t ctext_bytes, size_t scale,
                           const char *test_name)
{
    uint32_t *dwords_actual = (uint32_t *) actual;
    uint32_t *dwords_expected = (uint32_t *) expected;
    uint32_t current_actual, current_expected;
    size_t len = ctext_bytes >> 2; // dwords in single-data ciphertext

    for (size_t i = 0; i < scale; ++i) {
        for (size_t j = 0; j < len; ++j) {
            current_actual = actual[i+j];
            current_expected = expected[j*scale + i];
            
            if (current_actual != current_expected) {
                test_fail("Ciphertexts in test %s differ. "
                    "Ciphertext: %d, index: %d, "
                    "expected value: 0x%08x, actual value: 0x%08x\n",
                    test_name, i, j, current_expected, current_actual);
            }
        }
    }

    test_pass("Success: ciphertexts in %s are equal.\n", test_name);
}

void test_bcrypt_hashpass_parallel(p_blf_ctx *p_state, blf_ctx **states,
                                   uint8_t *hashes_actual, uint8_t *hashes_expected,
                                   const char *keys, uint64_t keybytes,
                                   const char *salt, uint64_t rounds,
                                   size_t scale)
{
    char test_name[] = "test_bcrypt_hashpass_parallel";
    // test_start(test_name)
    bcrypt_hashpass_parallel(p_state, salt, keys, keybytes, hashes_actual, rounds);

    for (size_t i = 0; i < scale; ++i) {
        bcrypt_hashpass_asm(states[i], salt, &keys[i*keybytes],
            keybytes, &hashes_expected[i*BCRYPT_HASH_BYTES], rounds);
    }

    compare_p_state_many(p_state, states, scale, test_name);
    compare_p_ciphertexts(hashes_actual, hashes_expected,
        BCRYPT_HASH_BYTES, scale, test_name);

}

void test_bcrypt_hashpass() {
    // Parallel state
    p_blf_ctx *p_state_actual;
    posix_memalign((void**) &p_state_actual, 32, sizeof(p_blf_ctx));
    blowfish_parallelise_state(&initstate_parallel, &initstate_asm);
    
    // Single-data states
    blf_ctx **states = malloc(DWORDS_PER_XMM * sizeof(blf_ctx *)); // expected single-data states
    blf_ctx *current;
    // Align single-data states
    for (size_t i = 0; i < DWORDS_PER_XMM; ++i) {
        posix_memalign((void**) &current, 32, sizeof(blf_ctx));
        states[i] = current;
    }

    char salt[] = "opabiniaOPABINIA";
    char keys[] = "anomalocarisGoLandcrabs!ANOMALOCARISgoLANDCRABS!";
    uint64_t keybytes = strlen(keys) / DWORDS_PER_XMM;

    uint8_t hashes_actual[BCRYPT_HASH_BYTES*DWORDS_PER_XMM];
    uint8_t hashes_expected[BCRYPT_HASH_BYTES*DWORDS_PER_XMM];

    uint64_t rounds = 8;

    test_bcrypt_hashpass_parallel(p_state_actual, states, hashes_actual, hashes_expected,
        keys, keybytes, salt, rounds, DWORDS_PER_XMM);

    free(p_state_actual);
    for (size_t i = 0; i < DWORDS_PER_XMM; ++i) {
        free(states[i]);
    }
    free(states);
}

int main(int argc, char const *argv[]) {
    blf_ctx *src;
    p_blf_ctx *state_expected;
    p_blf_ctx *state_actual;

    posix_memalign((void**) &src, 32, sizeof(blf_ctx));
    posix_memalign((void**) &state_expected, 32, sizeof(p_blf_ctx));
    posix_memalign((void**) &state_actual, 32, sizeof(p_blf_ctx));

    Blowfish_initstate(src);

    test_blowfish_parallelise_state(state_expected, src, DWORDS_PER_XMM);
    test_blowfish_init_state_parallel(state_actual, state_expected);

    uint32_t bytes_actual[4] = {0xdeadbeef, 0x00c0ffee, 0xfeedbeef, 0x00faece5};
    uint32_t bytes_expected[4] = {0xdeadbeef, 0x00c0ffee, 0xfeedbeef, 0x00faece5};
    test_f_xmm(state_actual, src, &bytes_actual, &bytes_expected);

    uint32_t xl_actual[4] = {0xdeadbeef, 0xfeedbeef, 0xbeefdead, 0xbeeffeed};
    uint32_t xr_actual[4] = {0xaac0ffee, 0xc0ffeeee, 0xc0ffffee, 0xc0ffee00};
    uint32_t xl_expected[4] = {0xdeadbeef, 0xfeedbeef, 0xbeefdead, 0xbeeffeed};
    uint32_t xr_expected[4] = {0xaac0ffee, 0xc0ffeeee, 0xc0ffffee, 0xc0ffee00};
    test_blowfish_round_xmm(state_actual, src, &xl_actual, &xr_actual,
        &xl_expected, &xr_expected, 1);

    blf_ctx **states = malloc(DWORDS_PER_XMM * sizeof(blf_ctx *)); // expected single-data states
    blf_ctx *current;
    // Initialise single-data states
    for (size_t i = 0; i < DWORDS_PER_XMM; ++i) {
        posix_memalign((void**) &current, 32, sizeof(blf_ctx));
        Blowfish_initstate(current);
        states[i] = current;
    }

    char salt[] = "opabiniaOPABINIA"; // 128 bits long
    char keys[] = "anomalocarisGoLandcrabs!ANOMALOCARISgoLANDCRABS!";
    uint64_t keybytes = strlen(keys) / DWORDS_PER_XMM;

    char data_actual[BCRYPT_HASH_BYTES*DWORDS_PER_XMM];
    char data_expected[BCRYPT_HASH_BYTES*DWORDS_PER_XMM];

    char final_data_actual[BCRYPT_HASH_BYTES];
    char final_data_expected[BCRYPT_HASH_BYTES];

    test_blowfish_expand_state_parallel(state_actual, states,
        &salt, &keys, keybytes, DWORDS_PER_XMM);
    test_blowfish_expand_0_state_parallel(state_actual, states,
        &keys, keybytes, DWORDS_PER_XMM);
    test_blowfish_expand_0_state_salt_parallel(state_actual, states,
        salt, DWORDS_PER_XMM);

    test_bcrypt_hashpass();

    test_copy_ctext_xmm(data_actual, data_expected, (const char *) &initial_p_ctext);

    return 0;
}