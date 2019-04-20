#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <malloc.h>
#include "bcrypt.h"
#include "bcrypt_constants.h"

// #define _POSIX_C_SOURCE 200112L

void blowfish_expand_state_asm(blf_ctx* state);

uint8_t* blowfish_encrypt(uint8_t* plaintext,
                          uint32_t plaintext_length,
                          uint8_t* key,
                          uint32_t key_length);

int main(int argc, char** argv) {
    blf_ctx* state;
    posix_memalign((void**) &state, 32, sizeof(blf_ctx));
    free(state);
    // uint8_t teststring[] = "cum squirter, nerd hurter\n";
    // uint8_t key[4] = "asss";
    // uint8_t* encrypted = blowfish_encrypt(teststring, 3, key, 32);
    // printf(encrypted);
    return 0;
}