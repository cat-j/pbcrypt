#include <stdio.h>
#include <stdlib.h>

#include "bcrypt-constants.h"
#include "bcrypt-macro-testing.h"
#include "bcrypt-parallel.h"
#include "openbsd.h"
#include "test.h"

#define DWORDS_PER_XMM 4

void test_blowfish_parallelise_state(p_blf_ctx *state_actual, blf_ctx *src,
                                     size_t scale)
{
    char test_name[] = "test_blowfish_parallelise_state";
    test_start(test_name, "");

    blowfish_parallelise_state(state_actual, src);

    compare_parallelised_state(state_actual, src, scale, test_name);
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

void test_blowfish_init_state_parallel(p_blf_ctx *state_actual,
                                       p_blf_ctx *state_expected)
{
    char test_name[] = "test_blowfish_init_state_parallel";
    test_start(test_name, "");
    blowfish_init_state_parallel(state_actual, state_expected);
    compare_p_states(state_actual, state_expected, DWORDS_PER_XMM, test_name);
}

void test_f_xmm(p_blf_ctx *p_state, blf_ctx *state,
                uint32_t *bytes_actual, uint32_t *bytes_expected)
{
    f_xmm(p_state, bytes_actual);

    for (size_t i = 0; i < DWORDS_PER_XMM; ++i) {}
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

    return 0;
}