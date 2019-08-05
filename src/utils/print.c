#include <stdio.h>

#include "print.h"

void print_hex(uint8_t *buf, size_t length) {
    printf("0x");
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}