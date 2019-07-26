#include "bcrypt.h"

char b64_encode_chart[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                           'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                           'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                           'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                           'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                           'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                           'w', 'x', 'y', 'z', '0', '1', '2', '3',
                           '4', '5', '6', '7', '8', '9', '+', '/'};

char b64_decode_chart[];

void b64_encode(char *dst, char *src, uint64_t srcbytes) {
    uint8_t data, sextet, next_highest_bits;
    uint64_t remaining_bits = (srcbytes << 3) % 6;
    uint64_t j = 0;

    for (uint64_t i = 0; i < srcbytes; ++i) {
        data = src[i];
        switch (i % 3) {
            case 0:
                sextet = data >> 2;
                next_highest_bits = (data & 3) << 4;
                break;
            
            case 1:
                sextet = (data >> 4) | next_highest_bits;
                next_highest_bits = (data & 0xf) << 2;
                break;
            
            case 2:
                sextet = (data >> 6) | next_highest_bits;
                break;
            
            default:
                break;
        }

        dst[j++] = b64_encode_chart[(uint64_t) sextet];
        if (i%3 == 2) dst[j++] = b64_encode_chart[data & 0x3f];
    }

    if (remaining_bits != 0) {
        dst[j++] = b64_encode_chart[(uint64_t) next_highest_bits];
        dst[j++] = '=';
        if (remaining_bits == 2) dst[j++] = '=';
    }
}

void b64_decode(char *dst, char *src, uint64_t srcbytes) {}