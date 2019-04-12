#include <stdint.h>
#include <stdio.h>

uint8_t* blowfish_encrypt(uint8_t* plaintext,
                          uint32_t plaintext_length,
                          uint8_t* key,
                          uint32_t key_length);

int main(int argc, char** argv) {
    uint8_t teststring[] = "cum squirter, nerd hurter\n";
    uint8_t key[4] = "asss";
    uint8_t* encrypted = blowfish_encrypt(teststring, 3, key, 32);
    printf(encrypted);
    return 0;
}