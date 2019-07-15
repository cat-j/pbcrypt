#include <assert.h>
// #include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "openbsd.h"
#include "../src/bcrypt.h" // TODO: figure out how to make "bcrypt.h" work
#include "../src/bcrypt_constants.h"

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

int main(int argc, char const *argv[]) {
    test_blowfish_init_state_asm();
    return 0;
}
