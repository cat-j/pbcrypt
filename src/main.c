#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <malloc.h>
#include "bcrypt.h"
#include "bcrypt_constants.h"

// #define _POSIX_C_SOURCE 200112L

// void blowfish_expand_state_asm(blf_ctx* state, const char* salt,
//                                const char* key, uint16_t keybytes)

uint8_t* blowfish_encrypt(uint8_t* plaintext,
                          uint32_t plaintext_length,
                          uint8_t* key,
                          uint32_t key_length);

int main(int argc, char** argv) {
    blf_ctx* state;
    posix_memalign((void**) &state, 32, sizeof(blf_ctx));
    
    char salt[16];
    for (int i = 0; i < 16; ++i)
        salt[i] = 'a';
    
    char key[9] = "assassas\0";
    
    blowfish_init_state_asm(state);
    blowfish_expand_state_asm(state, (const char*) &salt, (const char*) &key, 9);
    
    free(state);

    return 0;
}